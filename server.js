/**
 * ============================================================================
 * MIT ACADEMIC PORTAL — SUPABASE-COMPATIBLE POSTGRESQL/SQLITE + AUTH + RLS SERVER
 * File: server.js
 *
 * Provides:
 * 1. Static web server for the MIT Academic Portal (index.html, js/*)
 * 2. Supabase GoTrue-compatible Authentication API (/auth/v1/*)
 *    - Email + password signup & sign-in with scrypt password hashing
 *    - HMAC-SHA256 JWT issuance, verification, refresh, and logout
 * 3. Supabase PostgREST-compatible Data & RPC API (/rest/v1/*)
 *    - Backed by persistent relational database (node:sqlite with Foreign Keys,
 *      UNIQUE constraints, and CHECK constraints matching 001_initial_schema.sql)
 *    - Strict server-side Row Level Security (RLS) matching 002_rls_policies.sql
 *    - Seeded with synthetic development/demo data from 003_seed_data.sql
 * ============================================================================
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// Load .env if present
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx > 0) {
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim();
      if (!process.env[key]) process.env[key] = val;
    }
  }
}

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.SUPABASE_JWT_SECRET || crypto.createHash('sha256').update('mit-academic-portal-jwt-secret-key-2026').digest('hex');

// Persistent relational database file
const DATA_DIR = path.join(__dirname, 'supabase', '.data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
const DB_FILE = process.env.MIT_DB_FILE || path.join(DATA_DIR, 'mit_portal_pg.sqlite');

const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;');

// ============================================================================
// 1. CRYPTOGRAPHIC HELPERS (Scrypt Password Hashing & JWT Signing)
// ============================================================================
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string') return false;
  const parts = storedHash.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const [, salt, originalHex] = parts;
  const derivedBuf = crypto.scryptSync(String(password), salt, 64);
  const originalBuf = Buffer.from(originalHex, 'hex');
  if (derivedBuf.length !== originalBuf.length) return false;
  return crypto.timingSafeEqual(derivedBuf, originalBuf);
}

function base64UrlEncode(input) {
  const str = typeof input === 'string' ? input : JSON.stringify(input);
  return Buffer.from(str, 'utf8').toString('base64url');
}

function base64UrlDecode(str) {
  return Buffer.from(str, 'base64url').toString('utf8');
}

function signJwt(payload, expiresInSec = 8 * 3600) {
  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const fullPayload = {
    jti: crypto.randomUUID(),
    aud: 'authenticated',
    role: 'authenticated',
    iat: nowSec,
    exp: nowSec + expiresInSec,
    ...payload
  };
  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(fullPayload);
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');
  return {
    token: `${encodedHeader}.${encodedPayload}.${signature}`,
    expires_in: expiresInSec,
    expires_at: nowSec + expiresInSec
  };
}

const revokedTokens = new Set();

function verifyJwt(token) {
  if (!token || typeof token !== 'string' || revokedTokens.has(token)) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts;
  const expectedSig = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');
  if (signature !== expectedSig) return null;
  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < nowSec) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// ============================================================================
// 2. NORMALIZATION HELPERS (Matching 002_rls_policies.sql & Frontend)
// ============================================================================
function normalizeDivisionCode(divStr) {
  const raw = String(divStr || '').trim().toUpperCase();
  if (!raw) return 'A';
  if (raw === 'ALL') return 'ALL';
  const m = /(?:DIVISION|DIV)\s+([A-Z0-9]+)/i.exec(raw);
  if (m) return m[1].toUpperCase();
  return raw.split(/[\s·,-]+/)[0] || raw;
}

function normalizeSemesterCode(semStr) {
  const raw = String(semStr || '').trim().toUpperCase();
  if (!raw) return '';
  const cleaned = raw.replace(/^SEMESTER\s+/i, '').replace(/^SEM\s+/i, '').trim();
  const romanMap = {
    I: '1', II: '2', III: '3', IV: '4',
    V: '5', VI: '6', VII: '7', VIII: '8'
  };
  return romanMap[cleaned] || cleaned;
}

function normalizeBatchCode(val) {
  const s = String(val || '').trim().toUpperCase();
  if (!s || s === 'ALL' || s === 'ALL BATCHES' || s === 'ENTIRE DIVISION') return 'ALL';
  return s;
}

function getMondayISO(dateInput = new Date()) {
  const d = typeof dateInput === 'string'
    ? new Date(dateInput + 'T00:00:00')
    : new Date(dateInput.getFullYear(), dateInput.getMonth(), dateInput.getDate());
  const day = d.getDay();
  const diff = day === 0 ? -6 : 1 - day;
  d.setDate(d.getDate() + diff);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

function addDaysISO(isoDate, days) {
  const [y, m, d] = isoDate.split('-').map(Number);
  const dt = new Date(y, m - 1, d);
  dt.setDate(dt.getDate() + days);
  const yyyy = dt.getFullYear();
  const mm = String(dt.getMonth() + 1).padStart(2, '0');
  const dd = String(dt.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

// ============================================================================
// 3. INITIALIZE RELATIONAL SCHEMA & SEED DATA (001 + 003)
// ============================================================================
function initializeDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS auth_users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      encrypted_password TEXT NOT NULL,
      raw_user_meta_data TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS departments (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE COLLATE NOCASE,
      code TEXT NOT NULL UNIQUE COLLATE NOCASE,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS courses (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE COLLATE NOCASE,
      code TEXT NOT NULL UNIQUE COLLATE NOCASE,
      department_id TEXT NOT NULL REFERENCES departments(id) ON DELETE RESTRICT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS profiles (
      id TEXT PRIMARY KEY,
      auth_user_id TEXT NOT NULL UNIQUE REFERENCES auth_users(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('student', 'faculty')),
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      initials TEXT NOT NULL DEFAULT 'MIT',
      phone TEXT,
      department_id TEXT REFERENCES departments(id) ON DELETE SET NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS students (
      id TEXT PRIMARY KEY,
      profile_id TEXT NOT NULL UNIQUE REFERENCES profiles(id) ON DELETE CASCADE,
      student_id TEXT NOT NULL UNIQUE COLLATE NOCASE,
      course TEXT NOT NULL,
      course_id TEXT REFERENCES courses(id) ON DELETE SET NULL,
      department_id TEXT NOT NULL REFERENCES departments(id) ON DELETE RESTRICT,
      semester TEXT NOT NULL,
      academic_year TEXT NOT NULL DEFAULT '2026–27',
      division TEXT NOT NULL DEFAULT 'A',
      batch TEXT NOT NULL DEFAULT 'B1',
      roll_no TEXT,
      date_of_birth TEXT,
      blood_group TEXT NOT NULL DEFAULT 'O+',
      category TEXT NOT NULL DEFAULT 'Open Merit',
      phone TEXT,
      enrollment_year INTEGER NOT NULL DEFAULT 2024 CHECK (enrollment_year >= 2000 AND enrollment_year <= 2100),
      advisor_name TEXT NOT NULL DEFAULT 'Dr. Rajeshwari Deshmukh',
      guardian_name TEXT,
      guardian_phone TEXT,
      address TEXT,
      sgpa REAL NOT NULL DEFAULT 8.50 CHECK (sgpa >= 0.0 AND sgpa <= 10.0),
      cgpa REAL NOT NULL DEFAULT 8.50 CHECK (cgpa >= 0.0 AND cgpa <= 10.0),
      semester_history TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive', 'Graduated', 'Suspended')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS faculty (
      id TEXT PRIMARY KEY,
      profile_id TEXT NOT NULL UNIQUE REFERENCES profiles(id) ON DELETE CASCADE,
      faculty_id TEXT NOT NULL UNIQUE COLLATE NOCASE,
      department_id TEXT NOT NULL REFERENCES departments(id) ON DELETE RESTRICT,
      designation TEXT NOT NULL DEFAULT 'Assistant Professor',
      status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive', 'On Leave')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS subjects (
      id TEXT PRIMARY KEY,
      code TEXT NOT NULL UNIQUE COLLATE NOCASE,
      name TEXT NOT NULL,
      course_id TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      faculty_id TEXT REFERENCES faculty(id) ON DELETE SET NULL,
      semester TEXT NOT NULL,
      credits INTEGER NOT NULL CHECK (credits > 0 AND credits <= 12),
      subject_type TEXT NOT NULL DEFAULT 'Lecture' CHECK (subject_type IN ('Lecture', 'Lab', 'Tutorial', 'Other')),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS student_subjects (
      id TEXT PRIMARY KEY,
      student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      academic_year TEXT NOT NULL DEFAULT '2026–27',
      semester TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE (student_id, subject_id, academic_year, semester)
    );

    CREATE TABLE IF NOT EXISTS attendance_sessions (
      id TEXT PRIMARY KEY,
      subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      faculty_id TEXT REFERENCES faculty(id) ON DELETE SET NULL,
      date TEXT NOT NULL,
      start_time TEXT NOT NULL DEFAULT '09:00',
      end_time TEXT NOT NULL DEFAULT '10:00',
      type TEXT NOT NULL DEFAULT 'Lecture' CHECK (type IN ('Lecture', 'Lab', 'Lab Practical', 'Tutorial', 'Seminar', 'Other')),
      division TEXT NOT NULL DEFAULT 'A',
      batch TEXT NOT NULL DEFAULT 'ALL',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      CHECK (start_time < end_time)
    );

    CREATE TABLE IF NOT EXISTS attendance_records (
      id TEXT PRIMARY KEY,
      attendance_session_id TEXT NOT NULL REFERENCES attendance_sessions(id) ON DELETE CASCADE,
      student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK (status IN ('Present', 'Absent', 'Late', 'Excused')),
      marked_at TEXT NOT NULL DEFAULT (datetime('now')),
      marked_by TEXT REFERENCES faculty(id) ON DELETE SET NULL,
      UNIQUE (attendance_session_id, student_id)
    );

    CREATE TABLE IF NOT EXISTS grades (
      id TEXT PRIMARY KEY,
      student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      academic_year TEXT NOT NULL DEFAULT '2026–27',
      semester TEXT NOT NULL,
      internal_1 REAL NOT NULL DEFAULT 0 CHECK (internal_1 >= 0 AND internal_1 <= 20),
      internal_2 REAL NOT NULL DEFAULT 0 CHECK (internal_2 >= 0 AND internal_2 <= 20),
      end_sem REAL NOT NULL DEFAULT 0 CHECK (end_sem >= 0 AND end_sem <= 60),
      total REAL NOT NULL DEFAULT 0 CHECK (total >= 0 AND total <= 100),
      grade TEXT NOT NULL CHECK (grade IN ('O', 'A+', 'A', 'B+', 'B', 'P', 'F')),
      updated_by TEXT REFERENCES faculty(id) ON DELETE SET NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE (student_id, subject_id, academic_year, semester)
    );

    CREATE TABLE IF NOT EXISTS notices (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      category TEXT NOT NULL CHECK (category IN ('Academic Notice', 'Examination Notice', 'College Announcement')),
      body TEXT NOT NULL,
      author_id TEXT REFERENCES profiles(id) ON DELETE SET NULL,
      author_label TEXT,
      published INTEGER NOT NULL DEFAULT 1,
      published_at TEXT NOT NULL DEFAULT (datetime('now')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS faculty_activity (
      id TEXT PRIMARY KEY,
      faculty_id TEXT NOT NULL REFERENCES faculty(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      description TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS timetables (
      id TEXT PRIMARY KEY,
      week_start TEXT NOT NULL UNIQUE,
      week_end TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft' CHECK (LOWER(status) IN ('draft', 'published')),
      created_by TEXT REFERENCES faculty(id) ON DELETE SET NULL,
      published_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      CHECK (week_start <= week_end)
    );

    CREATE TABLE IF NOT EXISTS timetable_entries (
      id TEXT PRIMARY KEY,
      timetable_id TEXT NOT NULL REFERENCES timetables(id) ON DELETE CASCADE,
      date TEXT NOT NULL,
      day TEXT NOT NULL CHECK (day IN ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')),
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      subject_id TEXT REFERENCES subjects(id) ON DELETE SET NULL,
      subject_code TEXT NOT NULL,
      subject_name TEXT NOT NULL,
      faculty_id TEXT REFERENCES faculty(id) ON DELETE SET NULL,
      course_id TEXT REFERENCES courses(id) ON DELETE SET NULL,
      department_id TEXT REFERENCES departments(id) ON DELETE SET NULL,
      semester TEXT NOT NULL,
      division TEXT NOT NULL,
      batch TEXT NOT NULL DEFAULT 'ALL',
      group_code TEXT NOT NULL DEFAULT 'ALL',
      room TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'Lecture' CHECK (type IN ('Lecture', 'Lab', 'Practical', 'Tutorial', 'Seminar', 'Other')),
      entry_status TEXT NOT NULL DEFAULT 'Scheduled' CHECK (entry_status IN ('Scheduled', 'Rescheduled', 'Cancelled')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      CHECK (start_time < end_time)
    );
  `);

  const existingDepts = db.prepare('SELECT COUNT(*) AS cnt FROM departments').get();
  if (existingDepts && existingDepts.cnt > 0) {
    return;
  }

  // Seed initial demo data matching 003_seed_data.sql
  db.exec('BEGIN TRANSACTION;');
  try {
    const deptComp = '11111111-1111-4111-8111-111111111101';
    const deptCs   = '11111111-1111-4111-8111-111111111102';
    const deptIt   = '11111111-1111-4111-8111-111111111103';
    const deptAiml = '11111111-1111-4111-8111-111111111104';
    const deptElec = '11111111-1111-4111-8111-111111111105';

    const insDept = db.prepare('INSERT INTO departments (id, name, code) VALUES (?, ?, ?)');
    insDept.run(deptComp, 'Computer Engineering', 'COMP');
    insDept.run(deptCs,   'Computer Science', 'CSE');
    insDept.run(deptIt,   'Information Technology', 'IT');
    insDept.run(deptAiml, 'Artificial Intelligence & Machine Learning', 'AIML');
    insDept.run(deptElec, 'Electrical Engineering', 'ELEC');

    const courseComp = '22222222-2222-4222-8222-222222222201';
    const courseIt   = '22222222-2222-4222-8222-222222222202';
    const courseAiml = '22222222-2222-4222-8222-222222222203';

    const insCourse = db.prepare('INSERT INTO courses (id, name, code, department_id) VALUES (?, ?, ?, ?)');
    insCourse.run(courseComp, 'B.Tech Computer Engineering', 'BTECH-COMP', deptComp);
    insCourse.run(courseIt,   'B.Tech Information Technology', 'BTECH-IT', deptIt);
    insCourse.run(courseAiml, 'B.Tech Artificial Intelligence & Machine Learning', 'BTECH-AIML', deptAiml);

    const authFac1 = '33333333-3333-4333-8333-333333333101';
    const authFac2 = '33333333-3333-4333-8333-333333333102';
    const authStu1 = '33333333-3333-4333-8333-333333333001';
    const authStu2 = '33333333-3333-4333-8333-333333333002';
    const authStu3 = '33333333-3333-4333-8333-333333333003';
    const authStu4 = '33333333-3333-4333-8333-333333333004';
    const authStu5 = '33333333-3333-4333-8333-333333333005';

    const insAuth = db.prepare('INSERT INTO auth_users (id, email, encrypted_password, raw_user_meta_data) VALUES (?, ?, ?, ?)');
    insAuth.run(authFac1, 'rajeshwari.deshmukh@mitmumbai.edu.in', hashPassword('FAC2026101'), JSON.stringify({ role: 'faculty', faculty_id: 'FAC2026101' }));
    insAuth.run(authFac2, 'vikram.joshi@mitmumbai.edu.in', hashPassword('FAC2026102'), JSON.stringify({ role: 'faculty', faculty_id: 'FAC2026102' }));
    insAuth.run(authStu1, 'princekumar.sharma@mitmumbai.edu.in', hashPassword('MIT2026001'), JSON.stringify({ role: 'student', student_id: 'MIT2026001' }));
    insAuth.run(authStu2, 'ananya.kulkarni@mitmumbai.edu.in', hashPassword('MIT2026002'), JSON.stringify({ role: 'student', student_id: 'MIT2026002' }));
    insAuth.run(authStu3, 'rohan.deshmukh@mitmumbai.edu.in', hashPassword('MIT2026003'), JSON.stringify({ role: 'student', student_id: 'MIT2026003' }));
    insAuth.run(authStu4, 'meera.joshi@mitmumbai.edu.in', hashPassword('MIT2026004'), JSON.stringify({ role: 'student', student_id: 'MIT2026004' }));
    insAuth.run(authStu5, 'siddharth.patil@mitmumbai.edu.in', hashPassword('MIT2026005'), JSON.stringify({ role: 'student', student_id: 'MIT2026005' }));

    const profFac1 = '44444444-4444-4444-8444-444444444101';
    const profFac2 = '44444444-4444-4444-8444-444444444102';
    const profStu1 = '44444444-4444-4444-8444-444444444001';
    const profStu2 = '44444444-4444-4444-8444-444444444002';
    const profStu3 = '44444444-4444-4444-8444-444444444003';
    const profStu4 = '44444444-4444-4444-8444-444444444004';
    const profStu5 = '44444444-4444-4444-8444-444444444005';

    const insProf = db.prepare('INSERT INTO profiles (id, auth_user_id, role, name, email, initials, phone, department_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    insProf.run(profFac1, authFac1, 'faculty', 'Dr. Rajeshwari Deshmukh', 'rajeshwari.deshmukh@mitmumbai.edu.in', 'RD', '+91 98200 10101', deptComp);
    insProf.run(profFac2, authFac2, 'faculty', 'Prof. Vikramaditya Joshi', 'vikram.joshi@mitmumbai.edu.in', 'VJ', '+91 98200 10102', deptComp);
    insProf.run(profStu1, authStu1, 'student', 'Princekumar Sharma', 'princekumar.sharma@mitmumbai.edu.in', 'PS', '+91 98204 51289', deptComp);
    insProf.run(profStu2, authStu2, 'student', 'Ananya Kulkarni', 'ananya.kulkarni@mitmumbai.edu.in', 'AK', '+91 98192 33410', deptComp);
    insProf.run(profStu3, authStu3, 'student', 'Rohan Deshmukh', 'rohan.deshmukh@mitmumbai.edu.in', 'RD', '+91 97654 11920', deptComp);
    insProf.run(profStu4, authStu4, 'student', 'Meera Joshi', 'meera.joshi@mitmumbai.edu.in', 'MJ', '+91 98231 66501', deptComp);
    insProf.run(profStu5, authStu5, 'student', 'Siddharth Patil', 'siddharth.patil@mitmumbai.edu.in', 'SP', '+91 99208 44123', deptComp);

    const fac1 = '55555555-5555-4555-8555-555555555101';
    const fac2 = '55555555-5555-4555-8555-555555555102';
    const insFac = db.prepare('INSERT INTO faculty (id, profile_id, faculty_id, department_id, designation, status) VALUES (?, ?, ?, ?, ?, ?)');
    insFac.run(fac1, profFac1, 'FAC2026101', deptComp, 'Associate Professor', 'Active');
    insFac.run(fac2, profFac2, 'FAC2026102', deptComp, 'Assistant Professor', 'Active');

    const stu1 = '66666666-6666-4666-8666-666666666001';
    const stu2 = '66666666-6666-4666-8666-666666666002';
    const stu3 = '66666666-6666-4666-8666-666666666003';
    const stu4 = '66666666-6666-4666-8666-666666666004';
    const stu5 = '66666666-6666-4666-8666-666666666005';

    const insStu = db.prepare(`
      INSERT INTO students (
        id, profile_id, student_id, course, course_id, department_id,
        semester, academic_year, division, batch, roll_no,
        date_of_birth, blood_group, category, phone, enrollment_year,
        advisor_name, guardian_name, guardian_phone, address,
        sgpa, cgpa, semester_history, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insStu.run(
      stu1, profStu1, 'MIT2026001', 'B.Tech Computer Engineering', courseComp, deptComp,
      'Semester V', '2026–27', 'Division A · Roll No. 14', 'B1', '14',
      '2005-08-14', 'O+', 'Open Merit', '+91 98204 51289', 2024,
      'Dr. Rajeshwari Deshmukh', 'Rajesh Sharma', '+91 98201 11402',
      'Flat 402, Shantiniketan Residency, Kothrud / Mumbai Campus Hostel Block C',
      9.56, 9.42,
      JSON.stringify([
        { sem: 'Semester I', ay: '2024–25', sgpa: 9.20, credits: 22, status: 'Passed with Distinction' },
        { sem: 'Semester II', ay: '2024–25', sgpa: 9.35, credits: 22, status: 'Passed with Distinction' },
        { sem: 'Semester III', ay: '2025–26', sgpa: 9.48, credits: 23, status: 'Passed with Distinction' },
        { sem: 'Semester IV', ay: '2025–26', sgpa: 9.52, credits: 23, status: 'Passed with Distinction' }
      ]),
      'Active'
    );

    insStu.run(
      stu2, profStu2, 'MIT2026002', 'B.Tech Computer Engineering', courseComp, deptComp,
      'Semester V', '2026–27', 'Division A · Roll No. 04', 'B1', '04',
      '2005-11-22', 'A+', 'Open Merit', '+91 98192 33410', 2024,
      'Dr. Rajeshwari Deshmukh', 'Milind Kulkarni', '+91 98190 77812',
      '12, Saraswati Baug, Dadar West, Mumbai 400028',
      9.68, 9.60,
      JSON.stringify([
        { sem: 'Semester I', ay: '2024–25', sgpa: 9.50, credits: 22, status: 'Passed with Distinction' },
        { sem: 'Semester II', ay: '2024–25', sgpa: 9.58, credits: 22, status: 'Passed with Distinction' },
        { sem: 'Semester III', ay: '2025–26', sgpa: 9.62, credits: 23, status: 'Passed with Distinction' },
        { sem: 'Semester IV', ay: '2025–26', sgpa: 9.68, credits: 23, status: 'Passed with Distinction' }
      ]),
      'Active'
    );

    insStu.run(
      stu3, profStu3, 'MIT2026003', 'B.Tech Computer Engineering', courseComp, deptComp,
      'Semester V', '2026–27', 'Division A · Roll No. 21', 'B1', '21',
      '2005-03-03', 'B+', 'Open Merit', '+91 97654 11920', 2024,
      'Dr. Rajeshwari Deshmukh', 'Sanjay Deshmukh', '+91 97650 88210',
      'Sector 7, Vashi, Navi Mumbai 400703',
      7.45, 7.62,
      JSON.stringify([
        { sem: 'Semester I', ay: '2024–25', sgpa: 7.80, credits: 22, status: 'First Class' },
        { sem: 'Semester II', ay: '2024–25', sgpa: 7.65, credits: 22, status: 'First Class' },
        { sem: 'Semester III', ay: '2025–26', sgpa: 7.50, credits: 23, status: 'First Class' },
        { sem: 'Semester IV', ay: '2025–26', sgpa: 7.45, credits: 23, status: 'First Class' }
      ]),
      'Active'
    );

    insStu.run(
      stu4, profStu4, 'MIT2026004', 'B.Tech Computer Engineering', courseComp, deptComp,
      'Semester V', '2026–27', 'Division A · Roll No. 29', 'B1', '29',
      '2005-05-19', 'AB+', 'Open Merit', '+91 98231 66501', 2024,
      'Dr. Rajeshwari Deshmukh', 'Prakash Joshi', '+91 98230 11900',
      '45, Prabhat Road, Pune / Mumbai Hostel Block A',
      8.85, 8.74,
      JSON.stringify([
        { sem: 'Semester I', ay: '2024–25', sgpa: 8.60, credits: 22, status: 'Passed with Distinction' },
        { sem: 'Semester II', ay: '2024–25', sgpa: 8.70, credits: 22, status: 'Passed with Distinction' },
        { sem: 'Semester III', ay: '2025–26', sgpa: 8.80, credits: 23, status: 'Passed with Distinction' },
        { sem: 'Semester IV', ay: '2025–26', sgpa: 8.85, credits: 23, status: 'Passed with Distinction' }
      ]),
      'Active'
    );

    insStu.run(
      stu5, profStu5, 'MIT2026005', 'B.Tech Computer Engineering', courseComp, deptComp,
      'Semester V', '2026–27', 'Division A · Roll No. 38', 'B1', '38',
      '2005-01-09', 'O+', 'Open Merit', '+91 99208 44123', 2024,
      'Dr. Rajeshwari Deshmukh', 'Ashok Patil', '+91 99200 44120',
      'Hiranandani Gardens, Powai, Mumbai 400076',
      8.32, 8.20,
      JSON.stringify([
        { sem: 'Semester I', ay: '2024–25', sgpa: 8.10, credits: 22, status: 'First Class' },
        { sem: 'Semester II', ay: '2024–25', sgpa: 8.15, credits: 22, status: 'First Class' },
        { sem: 'Semester III', ay: '2025–26', sgpa: 8.25, credits: 23, status: 'Passed with Distinction' },
        { sem: 'Semester IV', ay: '2025–26', sgpa: 8.32, credits: 23, status: 'Passed with Distinction' }
      ]),
      'Active'
    );

    const subCs501 = '77777777-7777-4777-8777-777777777501';
    const subCs502 = '77777777-7777-4777-8777-777777777502';
    const subCs503 = '77777777-7777-4777-8777-777777777503';
    const subCs504 = '77777777-7777-4777-8777-777777777504';
    const subCs505 = '77777777-7777-4777-8777-777777777505';

    const insSub = db.prepare('INSERT INTO subjects (id, code, name, course_id, faculty_id, semester, credits, subject_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    insSub.run(subCs501, 'CS501', 'Design & Analysis of Algorithms', courseComp, fac1, 'Semester V', 4, 'Lecture');
    insSub.run(subCs502, 'CS502', 'Operating Systems',               courseComp, fac1, 'Semester V', 4, 'Lecture');
    insSub.run(subCs503, 'CS503', 'Database Management Systems',     courseComp, fac1, 'Semester V', 4, 'Lecture');
    insSub.run(subCs504, 'CS504', 'Computer Networks',               courseComp, fac2, 'Semester V', 4, 'Lecture');
    insSub.run(subCs505, 'CS505', 'Software Engineering & Testing',  courseComp, fac2, 'Semester V', 3, 'Lecture');

    const studentUuids = [stu1, stu2, stu3, stu4, stu5];
    const subjectUuids = [subCs501, subCs502, subCs503, subCs504, subCs505];
    const insEnroll = db.prepare('INSERT INTO student_subjects (id, student_id, subject_id, academic_year, semester) VALUES (?, ?, ?, ?, ?)');
    for (const sId of studentUuids) {
      for (const subId of subjectUuids) {
        insEnroll.run(crypto.randomUUID(), sId, subId, '2026–27', 'Semester V');
      }
    }

    const insGrade = db.prepare(`
      INSERT INTO grades (id, student_id, subject_id, academic_year, semester, internal_1, internal_2, end_sem, total, grade, updated_by)
      VALUES (?, ?, ?, '2026–27', 'Semester V', ?, ?, ?, ?, ?, ?)
    `);
    const gradesSeed = [
      // MIT2026001
      [stu1, subCs501, 19, 18, 56, 93, 'O', fac1],
      [stu1, subCs502, 18, 19, 54, 91, 'O', fac1],
      [stu1, subCs503, 17, 18, 52, 87, 'A+', fac1],
      [stu1, subCs504, 18, 17, 51, 86, 'A+', fac2],
      [stu1, subCs505, 19, 19, 55, 93, 'O', fac2],
      // MIT2026002
      [stu2, subCs501, 20, 19, 57, 96, 'O', fac1],
      [stu2, subCs502, 19, 19, 56, 94, 'O', fac1],
      [stu2, subCs503, 19, 20, 55, 94, 'O', fac1],
      [stu2, subCs504, 18, 18, 52, 88, 'A+', fac2],
      [stu2, subCs505, 19, 18, 54, 91, 'O', fac2],
      // MIT2026003
      [stu3, subCs501, 12, 13, 38, 63, 'B+', fac1],
      [stu3, subCs502, 13, 11, 36, 60, 'B', fac1],
      [stu3, subCs503, 14, 14, 41, 69, 'B+', fac1],
      [stu3, subCs504, 12, 13, 39, 64, 'B', fac2],
      [stu3, subCs505, 15, 14, 42, 71, 'A', fac2],
      // MIT2026004
      [stu4, subCs501, 16, 17, 48, 81, 'A+', fac1],
      [stu4, subCs502, 17, 16, 47, 80, 'A', fac1],
      [stu4, subCs503, 18, 17, 50, 85, 'A+', fac1],
      [stu4, subCs504, 16, 16, 46, 78, 'A', fac2],
      [stu4, subCs505, 18, 17, 49, 84, 'A+', fac2],
      // MIT2026005
      [stu5, subCs501, 15, 16, 44, 75, 'A', fac1],
      [stu5, subCs502, 15, 15, 43, 73, 'A', fac1],
      [stu5, subCs503, 16, 15, 45, 76, 'A', fac1],
      [stu5, subCs504, 14, 15, 42, 71, 'B+', fac2],
      [stu5, subCs505, 16, 16, 46, 78, 'A', fac2]
    ];
    for (const g of gradesSeed) {
      insGrade.run(crypto.randomUUID(), ...g);
    }

    // Seed Attendance Sessions & Records so attendance % is calculated from real records
    const insAttSession = db.prepare(`
      INSERT INTO attendance_sessions (id, subject_id, faculty_id, date, start_time, end_time, type, division, batch)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'A', 'ALL')
    `);
    const insAttRecord = db.prepare(`
      INSERT INTO attendance_records (id, attendance_session_id, student_id, status, marked_by)
      VALUES (?, ?, ?, ?, ?)
    `);

    const subjectAttendanceSpec = [
      { subId: subCs501, facId: fac1, total: 42, endDate: '2026-10-05', start: '09:00', end: '10:00', lastType: 'Lecture', attendedCounts: [39, 41, 27, 36, 33] },
      { subId: subCs502, facId: fac1, total: 40, endDate: '2026-10-04', start: '10:15', end: '11:15', lastType: 'Lab Practical', attendedCounts: [38, 39, 26, 34, 32] },
      { subId: subCs503, facId: fac1, total: 40, endDate: '2026-10-04', start: '11:30', end: '12:30', lastType: 'Lecture', attendedCounts: [36, 38, 28, 35, 33] },
      { subId: subCs504, facId: fac2, total: 38, endDate: '2026-10-03', start: '14:15', end: '15:15', lastType: 'Lecture', attendedCounts: [35, 36, 26, 33, 31] },
      { subId: subCs505, facId: fac2, total: 30, endDate: '2026-10-01', start: '15:30', end: '16:30', lastType: 'Tutorial', attendedCounts: [28, 29, 21, 27, 25] }
    ];

    for (const spec of subjectAttendanceSpec) {
      for (let i = 1; i <= spec.total; i++) {
        const sessId = crypto.randomUUID();
        const sessDate = addDaysISO(spec.endDate, -(spec.total - i));
        const sessType = i === spec.total ? spec.lastType : 'Lecture';
        insAttSession.run(sessId, spec.subId, spec.facId, sessDate, spec.start, spec.end, sessType);
        for (let sIdx = 0; sIdx < studentUuids.length; sIdx++) {
          const stuUuid = studentUuids[sIdx];
          const targetPresent = spec.attendedCounts[sIdx];
          // Make the latest session Present for stu1/2/4/5 and Absent for stu3 on CS501/CS502
          let isPresent;
          if (i === spec.total) {
            isPresent = !(sIdx === 2 && (spec.subId === subCs501 || spec.subId === subCs502));
          } else {
            const latestWasPresent = !(sIdx === 2 && (spec.subId === subCs501 || spec.subId === subCs502)) ? 1 : 0;
            const neededEarlier = targetPresent - latestWasPresent;
            isPresent = i <= neededEarlier;
          }
          insAttRecord.run(crypto.randomUUID(), sessId, stuUuid, isPresent ? 'Present' : 'Absent', spec.facId);
        }
      }
    }

    // Seed Notices
    const insNotice = db.prepare(`
      INSERT INTO notices (id, title, category, body, author_id, author_label, published, published_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
    `);
    insNotice.run(
      '99999999-9999-4999-8999-999999999001',
      'Semester V Mid-Term Examination Schedule (AY 2026–27)',
      'Examination Notice',
      'Mid-Term written examinations for B.Tech Semester V will commence from 19 October 2026. Students must carry their validated MIT Identity Card and Hall Ticket to the examination hall.',
      profFac1,
      'Controller of Examinations, MIT',
      '2026-10-04T09:00:00Z',
      '2026-10-04T09:00:00Z'
    );
    insNotice.run(
      '99999999-9999-4999-8999-999999999002',
      'Minimum 75% Attendance Compliance Circular',
      'Academic Notice',
      'As per Maharashtra Institute of Technology academic ordinances, students maintaining less than 75% attendance in lectures and laboratory sessions will not be granted term-work certification.',
      profFac1,
      'Dr. Rajeshwari Deshmukh · Dept. of Computer Engineering',
      '2026-10-02T11:00:00Z',
      '2026-10-02T11:00:00Z'
    );
    insNotice.run(
      '99999999-9999-4999-8999-999999999003',
      'Annual Convocation & Founders Day Academic Symposium',
      'College Announcement',
      'The 39th Annual Institutional Research & Innovation Symposium will be held in the Main Auditorium on 24 October 2026. Final and pre-final year students are invited to submit project abstracts.',
      profFac1,
      'Office of the Dean (Academic Affairs)',
      '2026-09-29T14:00:00Z',
      '2026-09-29T14:00:00Z'
    );
    insNotice.run(
      '99999999-9999-4999-8999-999999999004',
      'CS503 Database Management Systems Laboratory Evaluation',
      'Academic Notice',
      'Internal continuous assessment for DBMS SQL indexing and query optimization experiments is scheduled in Systems Lab 2 this Friday.',
      profFac1,
      'Dr. Rajeshwari Deshmukh · Dept. of Computer Engineering',
      '2026-09-27T16:00:00Z',
      '2026-09-27T16:00:00Z'
    );

    // Seed Faculty Activity
    const insAct = db.prepare(`
      INSERT INTO faculty_activity (id, faculty_id, action, description, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    insAct.run(crypto.randomUUID(), fac1, 'Recorded attendance', 'Recorded Lecture Attendance for CS501 (Design & Analysis of Algorithms) · Div A', '2026-10-05T10:35:00Z');
    insAct.run(crypto.randomUUID(), fac1, 'Updated grades', 'Updated Internal Assessment II marks for CS503 (Database Management Systems)', '2026-10-04T16:15:00Z');
    insAct.run(crypto.randomUUID(), fac1, 'Published notice', 'Published Academic Notice: Minimum 75% Attendance Compliance Circular', '2026-10-02T11:00:00Z');
    insAct.run(crypto.randomUUID(), fac1, 'Reviewed attendance', 'Reviewed low-attendance defaulter list for B.Tech Semester V', '2026-09-29T15:00:00Z');

    // Seed Current Week Timetable
    const weekStart = getMondayISO(new Date());
    const weekEnd = addDaysISO(weekStart, 5);
    const ttId = '88888888-8888-4888-8888-888888888001';

    db.prepare(`
      INSERT INTO timetables (id, week_start, week_end, status, created_by, published_at)
      VALUES (?, ?, ?, 'published', ?, datetime('now'))
    `).run(ttId, weekStart, weekEnd, fac1);

    const dMon = weekStart;
    const dTue = addDaysISO(weekStart, 1);
    const dWed = addDaysISO(weekStart, 2);
    const dThu = addDaysISO(weekStart, 3);
    const dFri = addDaysISO(weekStart, 4);
    const dSat = addDaysISO(weekStart, 5);

    const insEntry = db.prepare(`
      INSERT INTO timetable_entries (
        id, timetable_id, date, day, start_time, end_time,
        subject_id, subject_code, subject_name, faculty_id,
        course_id, department_id, semester, division, batch, group_code, room, type, entry_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Semester V', ?, ?, ?, ?, ?, 'Scheduled')
    `);

    const seedEntries = [
      ['tte_mon_1',  dMon, 'Monday',    '09:00', '10:00', subCs501, 'CS501', 'Design & Analysis of Algorithms', fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-302 · Aryabhatta Block', 'Lecture'],
      ['tte_mon_2',  dMon, 'Monday',    '10:15', '11:15', subCs502, 'CS502', 'Operating Systems Principles',    fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-304 · Aryabhatta Block', 'Lecture'],
      ['tte_mon_3',  dMon, 'Monday',    '11:30', '13:30', subCs503, 'CS503', 'Database Management Systems',     fac1, courseComp, deptComp, 'A', 'B1',  'G1',  'Systems Lab 2',             'Lab'],
      ['tte_mon_4',  dMon, 'Monday',    '14:15', '15:15', subCs504, 'CS504', 'Computer Networks & Security',    fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-305 · Ramanujan Hall',   'Lecture'],
      ['tte_mon_b1', dMon, 'Monday',    '10:15', '11:15', subCs501, 'CS501', 'Design & Analysis of Algorithms', fac1, courseComp, deptComp, 'B', 'ALL', 'ALL', 'LH-306 · Aryabhatta Block', 'Lecture'],
      ['tte_tue_1',  dTue, 'Tuesday',   '09:00', '10:00', subCs503, 'CS503', 'Database Management Systems',     fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-302 · Aryabhatta Block', 'Lecture'],
      ['tte_tue_2',  dTue, 'Tuesday',   '10:15', '11:15', subCs505, 'CS505', 'Software Engineering & Agile',    fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'Seminar Hall 1 · Tilak Bhavan', 'Lecture'],
      ['tte_tue_3',  dTue, 'Tuesday',   '11:30', '12:30', subCs501, 'CS501', 'Design & Analysis of Algorithms', fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'Tutorial Room 204',         'Tutorial'],
      ['tte_wed_1',  dWed, 'Wednesday', '09:00', '10:00', subCs502, 'CS502', 'Operating Systems Principles',    fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-304 · Aryabhatta Block', 'Lecture'],
      ['tte_wed_2',  dWed, 'Wednesday', '10:15', '11:15', subCs501, 'CS501', 'Design & Analysis of Algorithms', fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-302 · Aryabhatta Block', 'Lecture'],
      ['tte_wed_3',  dWed, 'Wednesday', '14:00', '16:00', subCs504, 'CS504', 'Computer Networks & Security',    fac2, courseComp, deptComp, 'A', 'B1',  'G1',  'Network Protocol Lab 4',    'Practical'],
      ['tte_thu_1',  dThu, 'Thursday',  '09:00', '10:00', subCs503, 'CS503', 'Database Management Systems',     fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-302 · Aryabhatta Block', 'Lecture'],
      ['tte_thu_2',  dThu, 'Thursday',  '11:30', '12:30', subCs505, 'CS505', 'Software Engineering & Agile',    fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'Seminar Hall 1 · Tilak Bhavan', 'Lecture'],
      ['tte_fri_1',  dFri, 'Friday',    '09:00', '11:00', subCs501, 'CS501', 'Design & Analysis of Algorithms', fac1, courseComp, deptComp, 'A', 'B1',  'G1',  'Algorithms & HPC Lab 1',    'Lab'],
      ['tte_fri_2',  dFri, 'Friday',    '11:30', '12:30', subCs504, 'CS504', 'Computer Networks & Security',    fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-305 · Ramanujan Hall',   'Lecture'],
      ['tte_sat_1',  dSat, 'Saturday',  '10:00', '12:00', subCs503, 'CS503', 'Database Management Systems',     fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'Systems Lab 2',             'Tutorial']
    ];

    for (const e of seedEntries) {
      insEntry.run(e[0], ttId, ...e.slice(1));
    }

    db.exec('COMMIT;');
  } catch (err) {
    db.exec('ROLLBACK;');
    throw err;
  }
}

initializeDatabase();

// ============================================================================
// 4. SERVER-SIDE AUTH CONTEXT & RLS ENFORCEMENT ENGINE
// ============================================================================
function getAuthContext(req) {
  const authHeader = req.headers['authorization'] || '';
  let token = null;
  if (authHeader.toLowerCase().startsWith('bearer ')) {
    token = authHeader.slice(7).trim();
  }
  if (!token) {
    return { authenticated: false, authUserId: null, role: 'anon', profile: null, student: null, faculty: null };
  }
  const payload = verifyJwt(token);
  if (!payload || !payload.sub) {
    return { authenticated: false, authUserId: null, role: 'anon', profile: null, student: null, faculty: null, token };
  }
  const authUser = db.prepare('SELECT id, email, raw_user_meta_data FROM auth_users WHERE id = ?').get(payload.sub);
  if (!authUser) {
    return { authenticated: false, authUserId: null, role: 'anon', profile: null, student: null, faculty: null, token };
  }
  const profile = db.prepare('SELECT * FROM profiles WHERE auth_user_id = ?').get(authUser.id);
  let student = null;
  let faculty = null;
  if (profile) {
    if (profile.role === 'student') {
      student = db.prepare('SELECT * FROM students WHERE profile_id = ?').get(profile.id);
    } else if (profile.role === 'faculty') {
      faculty = db.prepare('SELECT * FROM faculty WHERE profile_id = ?').get(profile.id);
    }
  }
  return {
    authenticated: true,
    token,
    authUserId: authUser.id,
    authEmail: authUser.email,
    userMeta: JSON.parse(authUser.raw_user_meta_data || '{}'),
    role: profile ? profile.role : 'authenticated',
    profile,
    student,
    faculty
  };
}

function rlsError(res, message = 'new row violates row-level security policy') {
  sendJson(res, 403, {
    code: '42501',
    details: null,
    hint: null,
    message
  });
}

// Filter rows for SELECT according to 002_rls_policies.sql
function filterRowsByRlsSelect(table, rows, ctx) {
  switch (table) {
    case 'departments':
    case 'courses':
    case 'subjects':
      return rows;

    case 'profiles':
      if (!ctx.authenticated) return [];
      if (ctx.role === 'faculty') return rows;
      return rows.filter(r => r.auth_user_id === ctx.authUserId || r.role === 'faculty');

    case 'students':
      if (!ctx.authenticated) return [];
      if (ctx.role === 'faculty') return rows;
      if (!ctx.profile) return [];
      return rows.filter(r => r.profile_id === ctx.profile.id);

    case 'faculty':
      if (!ctx.authenticated) return [];
      return rows;

    case 'student_subjects':
    case 'attendance_records':
    case 'grades':
      if (!ctx.authenticated) return [];
      if (ctx.role === 'faculty') return rows;
      if (!ctx.student) return [];
      return rows.filter(r => r.student_id === ctx.student.id);

    case 'attendance_sessions':
      if (!ctx.authenticated) return [];
      if (ctx.role === 'faculty') return rows;
      if (!ctx.student) return [];
      return rows;

    case 'notices':
      if (!ctx.authenticated) return [];
      if (ctx.role === 'faculty') return rows;
      return rows.filter(r => Boolean(r.published));

    case 'faculty_activity':
      if (!ctx.authenticated || ctx.role !== 'faculty') return [];
      return rows;

    case 'timetables':
      if (!ctx.authenticated) return [];
      if (ctx.role === 'faculty') return rows;
      return rows.filter(r => String(r.status || '').toLowerCase() === 'published');

    case 'timetable_entries': {
      if (!ctx.authenticated) return [];
      if (ctx.role === 'faculty') return rows;
      if (!ctx.student) return [];
      const stuDiv = normalizeDivisionCode(ctx.student.division);
      const stuSem = normalizeSemesterCode(ctx.student.semester);
      const stuBatch = normalizeBatchCode(ctx.student.batch);
      const publishedTtIds = new Set(
        db.prepare("SELECT id FROM timetables WHERE LOWER(status) = 'published'").all().map(t => t.id)
      );
      return rows.filter(r => {
        if (!publishedTtIds.has(r.timetable_id)) return false;
        if (r.department_id && ctx.student.department_id && r.department_id !== ctx.student.department_id) return false;
        if (normalizeSemesterCode(r.semester) !== stuSem) return false;
        const entryDiv = normalizeDivisionCode(r.division);
        if (entryDiv !== 'ALL' && stuDiv !== 'ALL' && entryDiv !== stuDiv) return false;
        const entryBatch = normalizeBatchCode(r.batch);
        if (entryBatch !== 'ALL' && stuBatch !== 'ALL' && entryBatch !== stuBatch) return false;
        return true;
      });
    }

    default:
      return [];
  }
}

// Check write permissions (INSERT / UPDATE / DELETE) according to 002_rls_policies.sql
function checkRlsWritePermission(table, method, payload, targetRow, ctx) {
  if (!ctx.authenticated) {
    return { allowed: false, message: `permission denied for table "${table}" (unauthenticated)` };
  }

  switch (table) {
    case 'profiles':
      if (method === 'POST') {
        if (payload.auth_user_id !== ctx.authUserId || payload.role !== 'student') {
          return { allowed: false, message: 'new row violates row-level security policy for table "profiles" (only self student profile allowed)' };
        }
        return { allowed: true };
      }
      if (method === 'PATCH') {
        if (!targetRow || targetRow.auth_user_id !== ctx.authUserId) {
          return { allowed: false, message: 'row-level security policy violation on update for table "profiles"' };
        }
        if (payload.role && payload.role !== targetRow.role) {
          return { allowed: false, message: 'cannot escalate role in table "profiles"' };
        }
        return { allowed: true };
      }
      return { allowed: false, message: 'delete not permitted on table "profiles"' };

    case 'students':
      if (method === 'POST') {
        if (!ctx.profile || ctx.profile.role !== 'student' || payload.profile_id !== ctx.profile.id) {
          return { allowed: false, message: 'new row violates row-level security policy for table "students"' };
        }
        return { allowed: true };
      }
      if (method === 'PATCH') {
        if (ctx.role === 'faculty') return { allowed: true };
        return { allowed: false, message: 'new row violates row-level security policy for table "students" (faculty only)' };
      }
      return { allowed: false, message: 'delete not permitted on table "students"' };

    case 'student_subjects':
      if (method === 'POST') {
        if (ctx.role === 'faculty') return { allowed: true };
        if (ctx.student && payload.student_id === ctx.student.id) return { allowed: true };
        return { allowed: false, message: 'new row violates row-level security policy for table "student_subjects"' };
      }
      if (ctx.role === 'faculty') return { allowed: true };
      return { allowed: false, message: 'row-level security policy violation on table "student_subjects"' };

    case 'faculty':
      // Faculty accounts CANNOT be created via public API
      if (method === 'POST' || method === 'DELETE') {
        return { allowed: false, message: 'new row violates row-level security policy for table "faculty"' };
      }
      if (method === 'PATCH' && ctx.role === 'faculty' && ctx.profile && targetRow && targetRow.profile_id === ctx.profile.id) {
        return { allowed: true };
      }
      return { allowed: false, message: 'row-level security policy violation on table "faculty"' };

    case 'departments':
    case 'courses':
    case 'subjects':
    case 'attendance_sessions':
    case 'attendance_records':
    case 'grades':
    case 'notices':
    case 'faculty_activity':
    case 'timetables':
    case 'timetable_entries':
      if (ctx.role === 'faculty') {
        return { allowed: true };
      }
      return {
        allowed: false,
        message: `new row violates row-level security policy for table "${table}"`
      };

    default:
      return { allowed: false, message: `unknown table "${table}"` };
  }
}

// ============================================================================
// 5. POSTGREST QUERY ENGINE (Filters, Ordering, Embedded Relations, Mutations)
// ============================================================================
const ALLOWED_TABLES = new Set([
  'departments', 'courses', 'profiles', 'students', 'faculty',
  'subjects', 'student_subjects', 'attendance_sessions', 'attendance_records',
  'grades', 'notices', 'faculty_activity', 'timetables', 'timetable_entries'
]);

function normalizeRowTypes(table, row) {
  if (!row) return row;
  const copy = { ...row };
  if (table === 'notices') {
    copy.published = Boolean(copy.published);
  }
  if (table === 'students' && typeof copy.semester_history === 'string') {
    try {
      copy.semester_history = JSON.parse(copy.semester_history);
    } catch (e) {
      copy.semester_history = [];
    }
  }
  if (table === 'students') {
    copy.sgpa = Number(copy.sgpa);
    copy.cgpa = Number(copy.cgpa);
  }
  if (table === 'grades') {
    copy.internal_1 = Number(copy.internal_1);
    copy.internal_2 = Number(copy.internal_2);
    copy.end_sem = Number(copy.end_sem);
    copy.total = Number(copy.total);
  }
  return copy;
}

function matchesPostgrestFilter(row, col, expr) {
  const val = row[col];
  if (expr.startsWith('eq.')) {
    const target = expr.slice(3);
    if (typeof val === 'boolean') return String(val) === target.toLowerCase();
    return String(val ?? '') === target;
  }
  if (expr.startsWith('ilike.')) {
    const pattern = expr.slice(6).toLowerCase().replace(/%/g, '.*').replace(/\*/g, '.*');
    return new RegExp(`^${pattern}$`, 'i').test(String(val ?? ''));
  }
  if (expr.startsWith('neq.')) {
    return String(val ?? '') !== expr.slice(4);
  }
  if (expr.startsWith('gt.')) {
    return Number(val) > Number(expr.slice(3)) || String(val) > expr.slice(3);
  }
  if (expr.startsWith('gte.')) {
    return Number(val) >= Number(expr.slice(4)) || String(val) >= expr.slice(4);
  }
  if (expr.startsWith('lt.')) {
    return Number(val) < Number(expr.slice(3)) || String(val) < expr.slice(3);
  }
  if (expr.startsWith('lte.')) {
    return Number(val) <= Number(expr.slice(4)) || String(val) <= expr.slice(4);
  }
  if (expr.startsWith('in.(') && expr.endsWith(')')) {
    const inner = expr.slice(4, -1);
    const items = inner.split(',').map(s => s.trim().replace(/^"|"$/g, ''));
    return items.includes(String(val ?? ''));
  }
  if (expr.startsWith('is.')) {
    const target = expr.slice(3).toLowerCase();
    if (target === 'null') return val === null || val === undefined;
    if (target === 'true') return Boolean(val) === true;
    if (target === 'false') return Boolean(val) === false;
  }
  return true;
}

function enrichRowRelations(table, row, selectParam, ctx) {
  if (!selectParam || !selectParam.includes('(')) return row;
  const enriched = { ...row };

  if (selectParam.includes('profiles(') && row.profile_id) {
    const p = db.prepare('SELECT * FROM profiles WHERE id = ?').get(row.profile_id);
    const visible = filterRowsByRlsSelect('profiles', p ? [normalizeRowTypes('profiles', p)] : [], ctx);
    enriched.profiles = visible[0] || null;
  }
  if (selectParam.includes('departments(') && row.department_id) {
    const d = db.prepare('SELECT * FROM departments WHERE id = ?').get(row.department_id);
    enriched.departments = d || null;
  }
  if (selectParam.includes('courses(') && row.course_id) {
    const c = db.prepare('SELECT * FROM courses WHERE id = ?').get(row.course_id);
    enriched.courses = c || null;
  }
  if (selectParam.includes('subjects(') && row.subject_id) {
    const s = db.prepare('SELECT * FROM subjects WHERE id = ?').get(row.subject_id);
    enriched.subjects = s || null;
  }
  if (selectParam.includes('faculty(') && row.faculty_id) {
    const f = db.prepare('SELECT * FROM faculty WHERE id = ?').get(row.faculty_id);
    if (f) {
      const fp = db.prepare('SELECT * FROM profiles WHERE id = ?').get(f.profile_id);
      enriched.faculty = { ...f, profiles: fp || null };
    } else {
      enriched.faculty = null;
    }
  }
  if (selectParam.includes('attendance_sessions(') && row.attendance_session_id) {
    const sess = db.prepare('SELECT * FROM attendance_sessions WHERE id = ?').get(row.attendance_session_id);
    if (sess) {
      const sub = db.prepare('SELECT * FROM subjects WHERE id = ?').get(sess.subject_id);
      enriched.attendance_sessions = { ...sess, subjects: sub || null };
    } else {
      enriched.attendance_sessions = null;
    }
  }
  if (selectParam.includes('timetable_entries(') && table === 'timetables') {
    const entries = db.prepare('SELECT * FROM timetable_entries WHERE timetable_id = ? ORDER BY date ASC, start_time ASC').all(row.id);
    const visibleEntries = filterRowsByRlsSelect('timetable_entries', entries.map(e => normalizeRowTypes('timetable_entries', e)), ctx);
    enriched.timetable_entries = visibleEntries.map(e => {
      if (e.faculty_id) {
        const f = db.prepare('SELECT * FROM faculty WHERE id = ?').get(e.faculty_id);
        const fp = f ? db.prepare('SELECT * FROM profiles WHERE id = ?').get(f.profile_id) : null;
        return { ...e, faculty: f ? { ...f, profiles: fp } : null };
      }
      return e;
    });
  }
  return enriched;
}

// ============================================================================
// 6. HTTP REQUEST ROUTER
// ============================================================================
function sendJson(res, status, data, extraHeaders = {}) {
  const body = status === 204 ? '' : JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, apikey, Prefer, X-Client-Info, x-supabase-api-version',
    'Access-Control-Expose-Headers': 'Content-Range, Preference-Applied',
    ...extraHeaders
  });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 2 * 1024 * 1024) {
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!raw.trim()) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(new Error('Invalid JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

function formatSupabaseUserObject(authUser) {
  const meta = typeof authUser.raw_user_meta_data === 'string'
    ? JSON.parse(authUser.raw_user_meta_data || '{}')
    : (authUser.raw_user_meta_data || {});
  return {
    id: authUser.id,
    aud: 'authenticated',
    role: 'authenticated',
    email: authUser.email,
    email_confirmed_at: authUser.created_at,
    app_metadata: { provider: 'email', providers: ['email'] },
    user_metadata: meta,
    created_at: authUser.created_at,
    updated_at: authUser.updated_at
  };
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, apikey, Prefer, X-Client-Info, x-supabase-api-version'
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  try {
    // ------------------------------------------------------------------------
    // A. SUPABASE AUTH ENDPOINTS (/auth/v1/*)
    // ------------------------------------------------------------------------
    if (pathname === '/auth/v1/signup' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      const userMeta = body.data || body.user_metadata || {};

      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
        return sendJson(res, 400, { error: 'invalid_grant', error_description: 'Please enter a valid institutional email address.' });
      }
      if (!password || password.length < 8) {
        return sendJson(res, 422, { error: 'weak_password', message: 'Password should be at least 8 characters.' });
      }

      const existing = db.prepare('SELECT id FROM auth_users WHERE LOWER(email) = LOWER(?)').get(email);
      if (existing) {
        return sendJson(res, 422, { code: 'user_already_exists', msg: 'User already registered', message: 'This email address is already registered. Please sign in instead.' });
      }

      // Security rule: public signup can NEVER set role = faculty
      const safeMeta = { ...userMeta, role: 'student' };
      const authId = crypto.randomUUID();
      const nowIso = new Date().toISOString();
      db.prepare(`
        INSERT INTO auth_users (id, email, encrypted_password, raw_user_meta_data, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(authId, email, hashPassword(password), JSON.stringify(safeMeta), nowIso, nowIso);

      const authUser = db.prepare('SELECT * FROM auth_users WHERE id = ?').get(authId);
      const userObj = formatSupabaseUserObject(authUser);
      const jwt = signJwt({ sub: authId, email });

      return sendJson(res, 200, {
        access_token: jwt.token,
        token_type: 'bearer',
        expires_in: jwt.expires_in,
        expires_at: jwt.expires_at,
        refresh_token: `ref_${crypto.randomBytes(24).toString('hex')}`,
        user: userObj,
        session: {
          access_token: jwt.token,
          token_type: 'bearer',
          expires_in: jwt.expires_in,
          expires_at: jwt.expires_at,
          refresh_token: `ref_${crypto.randomBytes(24).toString('hex')}`,
          user: userObj
        }
      });
    }

    if (pathname === '/auth/v1/token' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');

      if (!email || !password) {
        return sendJson(res, 400, { error: 'invalid_grant', error_description: 'Invalid login credentials' });
      }

      const authUser = db.prepare('SELECT * FROM auth_users WHERE LOWER(email) = LOWER(?)').get(email);
      if (!authUser || !verifyPassword(password, authUser.encrypted_password)) {
        return sendJson(res, 400, { error: 'invalid_grant', error_description: 'Invalid login credentials', message: 'Invalid login credentials' });
      }

      const userObj = formatSupabaseUserObject(authUser);
      const jwt = signJwt({ sub: authUser.id, email: authUser.email });
      const refreshToken = `ref_${crypto.randomBytes(24).toString('hex')}`;

      return sendJson(res, 200, {
        access_token: jwt.token,
        token_type: 'bearer',
        expires_in: jwt.expires_in,
        expires_at: jwt.expires_at,
        refresh_token: refreshToken,
        user: userObj
      });
    }

    if (pathname === '/auth/v1/user' && req.method === 'GET') {
      const ctx = getAuthContext(req);
      if (!ctx.authenticated) {
        return sendJson(res, 401, { message: 'Invalid or expired JWT token' });
      }
      const authUser = db.prepare('SELECT * FROM auth_users WHERE id = ?').get(ctx.authUserId);
      return sendJson(res, 200, formatSupabaseUserObject(authUser));
    }

    if (pathname === '/auth/v1/logout' && req.method === 'POST') {
      const ctx = getAuthContext(req);
      if (ctx.token) {
        revokedTokens.add(ctx.token);
      }
      return sendJson(res, 204, null);
    }

    // Development-only Demo Test Account Session Helper (So no passwords exist in frontend HTML/JS)
    if (pathname === '/auth/v1/demo-session' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const preset = String(body.preset || '');
      const presetMap = {
        student1: { id: 'MIT2026001', email: 'princekumar.sharma@mitmumbai.edu.in', role: 'student' },
        student2: { id: 'MIT2026002', email: 'ananya.kulkarni@mitmumbai.edu.in', role: 'student' },
        faculty1: { id: 'FAC2026101', email: 'rajeshwari.deshmukh@mitmumbai.edu.in', role: 'faculty' }
      };
      const target = presetMap[preset];
      if (!target) {
        return sendJson(res, 400, { message: 'Unknown demo preset' });
      }
      const authUser = db.prepare('SELECT * FROM auth_users WHERE LOWER(email) = LOWER(?)').get(target.email);
      if (!authUser) {
        return sendJson(res, 404, { message: 'Demo account not found' });
      }
      const userObj = formatSupabaseUserObject(authUser);
      const jwt = signJwt({ sub: authUser.id, email: authUser.email });
      return sendJson(res, 200, {
        institute_id: target.id,
        email: target.email,
        role: target.role,
        access_token: jwt.token,
        token_type: 'bearer',
        expires_in: jwt.expires_in,
        expires_at: jwt.expires_at,
        refresh_token: `ref_${crypto.randomBytes(24).toString('hex')}`,
        user: userObj
      });
    }

    // ------------------------------------------------------------------------
    // B. SUPABASE RPC ENDPOINTS (/rest/v1/rpc/*)
    // ------------------------------------------------------------------------
    if (pathname === '/rest/v1/rpc/resolve_institutional_login_email' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const ident = String(body.p_identifier || '').trim();
      if (!ident) return sendJson(res, 200, []);

      if (ident.includes('@')) {
        const p = db.prepare('SELECT email, role FROM profiles WHERE LOWER(email) = LOWER(?) LIMIT 1').get(ident);
        return sendJson(res, 200, p ? [p] : []);
      }

      const stu = db.prepare(`
        SELECT p.email, p.role
        FROM students s
        JOIN profiles p ON p.id = s.profile_id
        WHERE UPPER(s.student_id) = UPPER(?)
        LIMIT 1
      `).get(ident);
      if (stu) return sendJson(res, 200, [stu]);

      const fac = db.prepare(`
        SELECT p.email, p.role
        FROM faculty f
        JOIN profiles p ON p.id = f.profile_id
        WHERE UPPER(f.faculty_id) = UPPER(?)
        LIMIT 1
      `).get(ident);
      return sendJson(res, 200, fac ? [fac] : []);
    }

    // ------------------------------------------------------------------------
    // C. SUPABASE POSTGREST TABLE ENDPOINTS (/rest/v1/<table>)
    // ------------------------------------------------------------------------
    if (pathname.startsWith('/rest/v1/')) {
      const table = pathname.slice('/rest/v1/'.length).split('/')[0];
      if (!ALLOWED_TABLES.has(table)) {
        return sendJson(res, 404, { message: `Relation "${table}" does not exist` });
      }

      const ctx = getAuthContext(req);
      const selectParam = parsedUrl.searchParams.get('select') || '*';
      const orderParam = parsedUrl.searchParams.get('order');
      const limitParam = parsedUrl.searchParams.get('limit');
      const offsetParam = parsedUrl.searchParams.get('offset');
      const onConflictParam = parsedUrl.searchParams.get('on_conflict');
      const preferHeader = String(req.headers['prefer'] || '');
      const acceptHeader = String(req.headers['accept'] || '');
      const wantsSingleObject = acceptHeader.includes('application/vnd.pgrst.object+json');

      const reservedParams = new Set(['select', 'order', 'limit', 'offset', 'on_conflict', 'columns']);
      const filterEntries = [];
      for (const [k, v] of parsedUrl.searchParams.entries()) {
        if (!reservedParams.has(k)) {
          filterEntries.push([k, v]);
        }
      }

      // 1. SELECT (GET)
      if (req.method === 'GET') {
        const allRows = db.prepare(`SELECT * FROM ${table}`).all().map(r => normalizeRowTypes(table, r));
        let visibleRows = filterRowsByRlsSelect(table, allRows, ctx);

        for (const [col, expr] of filterEntries) {
          visibleRows = visibleRows.filter(r => matchesPostgrestFilter(r, col, expr));
        }

        if (orderParam) {
          const orders = orderParam.split(',').map(part => {
            const [col, dir] = part.trim().split('.');
            return { col, desc: String(dir || '').toLowerCase() === 'desc' };
          });
          visibleRows.sort((a, b) => {
            for (const o of orders) {
              const va = a[o.col] ?? '';
              const vb = b[o.col] ?? '';
              if (va < vb) return o.desc ? 1 : -1;
              if (va > vb) return o.desc ? -1 : 1;
            }
            return 0;
          });
        }

        if (offsetParam) {
          visibleRows = visibleRows.slice(Number(offsetParam));
        }
        if (limitParam) {
          visibleRows = visibleRows.slice(0, Number(limitParam));
        }

        const enriched = visibleRows.map(r => enrichRowRelations(table, r, selectParam, ctx));

        if (wantsSingleObject) {
          if (enriched.length !== 1) {
            return sendJson(res, 406, {
              code: 'PGRST116',
              details: `The result contains ${enriched.length} rows`,
              hint: null,
              message: 'JSON object requested, multiple (or no) rows returned'
            });
          }
          return sendJson(res, 200, enriched[0]);
        }
        return sendJson(res, 200, enriched);
      }

      // 2. INSERT / UPSERT (POST)
      if (req.method === 'POST') {
        const body = await readJsonBody(req);
        const items = Array.isArray(body) ? body : [body];
        const insertedRows = [];

        db.exec('BEGIN TRANSACTION;');
        try {
          for (const rawItem of items) {
            const item = { ...rawItem };
            if (!item.id) item.id = crypto.randomUUID();

            const rlsCheck = checkRlsWritePermission(table, 'POST', item, null, ctx);
            if (!rlsCheck.allowed) {
              db.exec('ROLLBACK;');
              return rlsError(res, rlsCheck.message);
            }

            // Prepare values for SQLite
            const dbItem = { ...item };
            if (table === 'notices' && typeof dbItem.published === 'boolean') {
              dbItem.published = dbItem.published ? 1 : 0;
            }
            if (table === 'students' && Array.isArray(dbItem.semester_history)) {
              dbItem.semester_history = JSON.stringify(dbItem.semester_history);
            }
            if (table === 'grades' && dbItem.total === undefined) {
              dbItem.total = Number(dbItem.internal_1 || 0) + Number(dbItem.internal_2 || 0) + Number(dbItem.end_sem || 0);
            }

            const cols = Object.keys(dbItem);
            const placeholders = cols.map(() => '?').join(', ');
            const isUpsert = preferHeader.includes('resolution=merge-duplicates') || Boolean(onConflictParam);

            if (isUpsert && onConflictParam) {
              const conflictCols = onConflictParam.split(',').map(c => c.trim());
              const updateAssignments = cols
                .filter(c => c !== 'id' && !conflictCols.includes(c))
                .map(c => `${c} = excluded.${c}`)
                .join(', ');
              const sql = updateAssignments
                ? `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders}) ON CONFLICT (${conflictCols.join(', ')}) DO UPDATE SET ${updateAssignments}`
                : `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders}) ON CONFLICT (${conflictCols.join(', ')}) DO NOTHING`;
              db.prepare(sql).run(...cols.map(c => dbItem[c]));

              const whereClause = conflictCols.map(c => `${c} = ?`).join(' AND ');
              const fetched = db.prepare(`SELECT * FROM ${table} WHERE ${whereClause}`).get(...conflictCols.map(c => dbItem[c]));
              if (fetched) insertedRows.push(enrichRowRelations(table, normalizeRowTypes(table, fetched), selectParam, ctx));
            } else {
              const sql = `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders})`;
              db.prepare(sql).run(...cols.map(c => dbItem[c]));

              // Trigger equivalent from 002_rls_policies.sql: initialize_new_student_enrollment()
              if (table === 'student_subjects') {
                db.prepare(`
                  INSERT INTO grades (id, student_id, subject_id, academic_year, semester, internal_1, internal_2, end_sem, total, grade)
                  VALUES (?, ?, ?, ?, ?, 0, 0, 0, 0, 'P')
                  ON CONFLICT (student_id, subject_id, academic_year, semester) DO NOTHING
                `).run(crypto.randomUUID(), dbItem.student_id, dbItem.subject_id, dbItem.academic_year || '2026–27', dbItem.semester || 'Semester V');
              }

              const fetched = db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(dbItem.id);
              if (fetched) insertedRows.push(enrichRowRelations(table, normalizeRowTypes(table, fetched), selectParam, ctx));
            }
          }
          db.exec('COMMIT;');
        } catch (dbErr) {
          try { db.exec('ROLLBACK;'); } catch (_) {}
          const msg = String(dbErr.message || 'Database constraint violation');
          const isUnique = msg.includes('UNIQUE constraint failed');
          return sendJson(res, isUnique ? 409 : 400, {
            code: isUnique ? '23505' : '23514',
            details: msg,
            message: msg
          });
        }

        if (wantsSingleObject) {
          return sendJson(res, 201, insertedRows[0] || {});
        }
        return sendJson(res, 201, insertedRows);
      }

      // 3. UPDATE (PATCH)
      if (req.method === 'PATCH') {
        const patchBody = await readJsonBody(req);
        const allRows = db.prepare(`SELECT * FROM ${table}`).all();
        let targetRows = allRows.filter(r => {
          for (const [col, expr] of filterEntries) {
            if (!matchesPostgrestFilter(normalizeRowTypes(table, r), col, expr)) return false;
          }
          return true;
        });

        for (const row of targetRows) {
          const check = checkRlsWritePermission(table, 'PATCH', patchBody, row, ctx);
          if (!check.allowed) {
            return rlsError(res, check.message);
          }
        }

        const updatedRows = [];
        db.exec('BEGIN TRANSACTION;');
        try {
          for (const row of targetRows) {
            const dbPatch = { ...patchBody };
            delete dbPatch.id;
            if (table === 'notices' && typeof dbPatch.published === 'boolean') {
              dbPatch.published = dbPatch.published ? 1 : 0;
            }
            if (table === 'students' && Array.isArray(dbPatch.semester_history)) {
              dbPatch.semester_history = JSON.stringify(dbPatch.semester_history);
            }
            const cols = Object.keys(dbPatch);
            if (cols.length > 0) {
              const setClause = cols.map(c => `${c} = ?`).join(', ');
              db.prepare(`UPDATE ${table} SET ${setClause} WHERE id = ?`).run(...cols.map(c => dbPatch[c]), row.id);
            }
            const refreshed = db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(row.id);
            if (refreshed) {
              updatedRows.push(enrichRowRelations(table, normalizeRowTypes(table, refreshed), selectParam, ctx));
            }
          }
          db.exec('COMMIT;');
        } catch (dbErr) {
          try { db.exec('ROLLBACK;'); } catch (_) {}
          return sendJson(res, 400, { code: '23514', message: String(dbErr.message) });
        }

        if (wantsSingleObject) {
          if (updatedRows.length !== 1) {
            return sendJson(res, 406, { code: 'PGRST116', message: 'JSON object requested, multiple (or no) rows returned' });
          }
          return sendJson(res, 200, updatedRows[0]);
        }
        return sendJson(res, 200, updatedRows);
      }

      // 4. DELETE
      if (req.method === 'DELETE') {
        const allRows = db.prepare(`SELECT * FROM ${table}`).all();
        const targetRows = allRows.filter(r => {
          for (const [col, expr] of filterEntries) {
            if (!matchesPostgrestFilter(normalizeRowTypes(table, r), col, expr)) return false;
          }
          return true;
        });

        for (const row of targetRows) {
          const check = checkRlsWritePermission(table, 'DELETE', {}, row, ctx);
          if (!check.allowed) {
            return rlsError(res, check.message);
          }
        }

        const deletedRows = [];
        db.exec('BEGIN TRANSACTION;');
        try {
          for (const row of targetRows) {
            deletedRows.push(normalizeRowTypes(table, row));
            db.prepare(`DELETE FROM ${table} WHERE id = ?`).run(row.id);
          }
          db.exec('COMMIT;');
        } catch (dbErr) {
          try { db.exec('ROLLBACK;'); } catch (_) {}
          return sendJson(res, 400, { code: '23503', message: String(dbErr.message) });
        }

        return sendJson(res, 200, deletedRows);
      }
    }

    // ------------------------------------------------------------------------
    // D. STATIC FILES (index.html, js/*, etc.)
    // ------------------------------------------------------------------------
    let relPath = pathname === '/' ? '/index.html' : pathname;
    relPath = path.normalize(relPath).replace(/^(\.\.(\/|\\|$))+/, '');
    const filePath = path.join(__dirname, relPath);

    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';
      const content = fs.readFileSync(filePath);
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache'
      });
      return res.end(content);
    }

    sendJson(res, 404, { error: 'Not Found' });
  } catch (err) {
    sendJson(res, 500, { error: 'Internal Server Error', message: 'An unexpected server error occurred.' });
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`MIT Academic Portal Supabase Backend + Web Server running at http://localhost:${PORT}`);
  });
}

module.exports = { server, db };
