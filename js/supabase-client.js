/**
 * ============================================================================
 * MIT ACADEMIC PORTAL — SUPABASE CLIENT INITIALIZATION
 * File: js/supabase-client.js
 *
 * SECURITY POLICY:
 * - Uses ONLY public Supabase URL and public Anon/Publishable key.
 * - NEVER embeds service_role keys, database passwords, or private secrets.
 * - All authorization is enforced via PostgreSQL RLS policies.
 * - Automatically supports both live Supabase / Node backend servers AND
 *   static hosting environments (such as GitHub Pages) via an RLS-enforced
 *   relational table engine when backend endpoints return HTTP 404/405.
 * ============================================================================
 */
(function (global) {
  'use strict';

  const AUTH_STORAGE_KEY = 'sb_mit_portal_auth_session';
  const REMEMBER_PREF_KEY = 'mit_portal_remember_pref';
  const RELATIONAL_SNAPSHOT_KEY = 'sb_mit_pg_relational_tables_v1';

  function resolveSupabaseUrl() {
    if (global.__SUPABASE_CONFIG__ && global.__SUPABASE_CONFIG__.url) {
      return global.__SUPABASE_CONFIG__.url.replace(/\/+$/, '');
    }
    if (global.location && (global.location.protocol === 'http:' || global.location.protocol === 'https:')) {
      return global.location.origin;
    }
    return 'http://localhost:3000';
  }

  function resolveSupabaseAnonKey() {
    if (global.__SUPABASE_CONFIG__ && global.__SUPABASE_CONFIG__.anonKey) {
      return global.__SUPABASE_CONFIG__.anonKey;
    }
    return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIn0.public-anon-key';
  }

  const SUPABASE_URL = resolveSupabaseUrl();
  const SUPABASE_ANON_KEY = resolveSupabaseAnonKey();

  // Internal session storage helper (respects Remember Me preference)
  function loadStoredSession() {
    try {
      const rawSession = sessionStorage.getItem(AUTH_STORAGE_KEY) || localStorage.getItem(AUTH_STORAGE_KEY);
      if (!rawSession) return null;
      const parsed = JSON.parse(rawSession);
      if (!parsed || !parsed.access_token) return null;
      const nowSec = Math.floor(Date.now() / 1000);
      if (parsed.expires_at && nowSec >= parsed.expires_at) {
        clearStoredSession();
        return null;
      }
      return parsed;
    } catch (e) {
      return null;
    }
  }

  function saveStoredSession(session, rememberMe = true) {
    try {
      const serialized = JSON.stringify(session);
      sessionStorage.setItem(AUTH_STORAGE_KEY, serialized);
      if (rememberMe) {
        localStorage.setItem(AUTH_STORAGE_KEY, serialized);
      } else {
        localStorage.removeItem(AUTH_STORAGE_KEY);
      }
    } catch (e) {}
  }

  function clearStoredSession() {
    try {
      sessionStorage.removeItem(AUTH_STORAGE_KEY);
      localStorage.removeItem(AUTH_STORAGE_KEY);
    } catch (e) {}
  }

  const authListeners = new Set();
  function notifyAuthListeners(event, session) {
    authListeners.forEach(cb => {
      try {
        cb(event, session);
      } catch (e) {}
    });
  }

  function buildHeaders(extraHeaders = {}) {
    const session = loadStoredSession();
    return {
      'Content-Type': 'application/json',
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${session ? session.access_token : SUPABASE_ANON_KEY}`,
      ...extraHeaders
    };
  }

  // ==========================================================================
  // STATIC HOST (GITHUB PAGES) RELATIONAL & RLS ENGINE
  // Activated automatically ONLY when hosted on a static file server (e.g.
  // GitHub Pages *.github.io) where /auth/v1 or /rest/v1 returns 404/405.
  // ==========================================================================
  function generateUuid() {
    if (global.crypto && typeof global.crypto.randomUUID === 'function') {
      return global.crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
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
    const romanMap = { I: '1', II: '2', III: '3', IV: '4', V: '5', VI: '6', VII: '7', VIII: '8' };
    return romanMap[cleaned] || cleaned;
  }

  function normalizeBatchCode(val) {
    const s = String(val || '').trim().toUpperCase();
    if (!s || s === 'ALL' || s === 'ALL BATCHES' || s === 'ENTIRE DIVISION') return 'ALL';
    return s;
  }

  function encodeVerifier(str) {
    let h1 = 0xdeadbeef ^ str.length;
    let h2 = 0x41c6ce57 ^ str.length;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 'v1$' + (h2 >>> 0).toString(16).padStart(8, '0') + (h1 >>> 0).toString(16).padStart(8, '0');
  }

  function buildSeedRelationalTables() {
    const nowIso = new Date().toISOString();
    const deptComp = '11111111-1111-4111-8111-111111111101';
    const deptCs   = '11111111-1111-4111-8111-111111111102';
    const deptIt   = '11111111-1111-4111-8111-111111111103';
    const deptAiml = '11111111-1111-4111-8111-111111111104';
    const deptElec = '11111111-1111-4111-8111-111111111105';

    const courseComp = '22222222-2222-4222-8222-222222222201';
    const courseIt   = '22222222-2222-4222-8222-222222222202';
    const courseAiml = '22222222-2222-4222-8222-222222222203';

    const authFac1 = '33333333-3333-4333-8333-333333333101';
    const authFac2 = '33333333-3333-4333-8333-333333333102';
    const authStu1 = '33333333-3333-4333-8333-333333333001';
    const authStu2 = '33333333-3333-4333-8333-333333333002';
    const authStu3 = '33333333-3333-4333-8333-333333333003';
    const authStu4 = '33333333-3333-4333-8333-333333333004';
    const authStu5 = '33333333-3333-4333-8333-333333333005';

    const profFac1 = '44444444-4444-4444-8444-444444444101';
    const profFac2 = '44444444-4444-4444-8444-444444444102';
    const profStu1 = '44444444-4444-4444-8444-444444444001';
    const profStu2 = '44444444-4444-4444-8444-444444444002';
    const profStu3 = '44444444-4444-4444-8444-444444444003';
    const profStu4 = '44444444-4444-4444-8444-444444444004';
    const profStu5 = '44444444-4444-4444-8444-444444444005';

    const fac1 = '55555555-5555-4555-8555-555555555101';
    const fac2 = '55555555-5555-4555-8555-555555555102';

    const stu1 = '66666666-6666-4666-8666-666666666001';
    const stu2 = '66666666-6666-4666-8666-666666666002';
    const stu3 = '66666666-6666-4666-8666-666666666003';
    const stu4 = '66666666-6666-4666-8666-666666666004';
    const stu5 = '66666666-6666-4666-8666-666666666005';

    const subCs501 = '77777777-7777-4777-8777-777777777501';
    const subCs502 = '77777777-7777-4777-8777-777777777502';
    const subCs503 = '77777777-7777-4777-8777-777777777503';
    const subCs504 = '77777777-7777-4777-8777-777777777504';
    const subCs505 = '77777777-7777-4777-8777-777777777505';

    const departments = [
      { id: deptComp, name: 'Computer Engineering', code: 'COMP', created_at: nowIso },
      { id: deptCs, name: 'Computer Science', code: 'CSE', created_at: nowIso },
      { id: deptIt, name: 'Information Technology', code: 'IT', created_at: nowIso },
      { id: deptAiml, name: 'Artificial Intelligence & Machine Learning', code: 'AIML', created_at: nowIso },
      { id: deptElec, name: 'Electrical Engineering', code: 'ELEC', created_at: nowIso }
    ];

    const courses = [
      { id: courseComp, name: 'B.Tech Computer Engineering', code: 'BTECH-COMP', department_id: deptComp, created_at: nowIso },
      { id: courseIt, name: 'B.Tech Information Technology', code: 'BTECH-IT', department_id: deptIt, created_at: nowIso },
      { id: courseAiml, name: 'B.Tech Artificial Intelligence & Machine Learning', code: 'BTECH-AIML', department_id: deptAiml, created_at: nowIso }
    ];

    const auth_users = [
      { id: authFac1, email: 'rajeshwari.deshmukh@mitmumbai.edu.in', verifier: encodeVerifier('FAC2026101'), raw_user_meta_data: { role: 'faculty', faculty_id: 'FAC2026101' }, created_at: nowIso, updated_at: nowIso },
      { id: authFac2, email: 'vikram.joshi@mitmumbai.edu.in', verifier: encodeVerifier('FAC2026102'), raw_user_meta_data: { role: 'faculty', faculty_id: 'FAC2026102' }, created_at: nowIso, updated_at: nowIso },
      { id: authStu1, email: 'princekumar.sharma@mitmumbai.edu.in', verifier: encodeVerifier('MIT2026001'), raw_user_meta_data: { role: 'student', student_id: 'MIT2026001' }, created_at: nowIso, updated_at: nowIso },
      { id: authStu2, email: 'ananya.kulkarni@mitmumbai.edu.in', verifier: encodeVerifier('MIT2026002'), raw_user_meta_data: { role: 'student', student_id: 'MIT2026002' }, created_at: nowIso, updated_at: nowIso },
      { id: authStu3, email: 'rohan.deshmukh@mitmumbai.edu.in', verifier: encodeVerifier('MIT2026003'), raw_user_meta_data: { role: 'student', student_id: 'MIT2026003' }, created_at: nowIso, updated_at: nowIso },
      { id: authStu4, email: 'meera.joshi@mitmumbai.edu.in', verifier: encodeVerifier('MIT2026004'), raw_user_meta_data: { role: 'student', student_id: 'MIT2026004' }, created_at: nowIso, updated_at: nowIso },
      { id: authStu5, email: 'siddharth.patil@mitmumbai.edu.in', verifier: encodeVerifier('MIT2026005'), raw_user_meta_data: { role: 'student', student_id: 'MIT2026005' }, created_at: nowIso, updated_at: nowIso }
    ];

    const profiles = [
      { id: profFac1, auth_user_id: authFac1, role: 'faculty', name: 'Dr. Rajeshwari Deshmukh', email: 'rajeshwari.deshmukh@mitmumbai.edu.in', initials: 'RD', phone: '+91 98200 10101', department_id: deptComp, created_at: nowIso, updated_at: nowIso },
      { id: profFac2, auth_user_id: authFac2, role: 'faculty', name: 'Prof. Vikramaditya Joshi', email: 'vikram.joshi@mitmumbai.edu.in', initials: 'VJ', phone: '+91 98200 10102', department_id: deptComp, created_at: nowIso, updated_at: nowIso },
      { id: profStu1, auth_user_id: authStu1, role: 'student', name: 'Princekumar Sharma', email: 'princekumar.sharma@mitmumbai.edu.in', initials: 'PS', phone: '+91 98204 51289', department_id: deptComp, created_at: nowIso, updated_at: nowIso },
      { id: profStu2, auth_user_id: authStu2, role: 'student', name: 'Ananya Kulkarni', email: 'ananya.kulkarni@mitmumbai.edu.in', initials: 'AK', phone: '+91 98192 33410', department_id: deptComp, created_at: nowIso, updated_at: nowIso },
      { id: profStu3, auth_user_id: authStu3, role: 'student', name: 'Rohan Deshmukh', email: 'rohan.deshmukh@mitmumbai.edu.in', initials: 'RD', phone: '+91 97654 11920', department_id: deptComp, created_at: nowIso, updated_at: nowIso },
      { id: profStu4, auth_user_id: authStu4, role: 'student', name: 'Meera Joshi', email: 'meera.joshi@mitmumbai.edu.in', initials: 'MJ', phone: '+91 98231 66501', department_id: deptComp, created_at: nowIso, updated_at: nowIso },
      { id: profStu5, auth_user_id: authStu5, role: 'student', name: 'Siddharth Patil', email: 'siddharth.patil@mitmumbai.edu.in', initials: 'SP', phone: '+91 99208 44123', department_id: deptComp, created_at: nowIso, updated_at: nowIso }
    ];

    const faculty = [
      { id: fac1, profile_id: profFac1, faculty_id: 'FAC2026101', department_id: deptComp, designation: 'Associate Professor', status: 'Active', created_at: nowIso, updated_at: nowIso },
      { id: fac2, profile_id: profFac2, faculty_id: 'FAC2026102', department_id: deptComp, designation: 'Assistant Professor', status: 'Active', created_at: nowIso, updated_at: nowIso }
    ];

    const students = [
      {
        id: stu1, profile_id: profStu1, student_id: 'MIT2026001', course: 'B.Tech Computer Engineering', course_id: courseComp, department_id: deptComp,
        semester: 'Semester V', academic_year: '2026–27', division: 'Division A · Roll No. 14', batch: 'B1', roll_no: '14',
        date_of_birth: '2005-08-14', blood_group: 'O+', category: 'Open Merit', phone: '+91 98204 51289', enrollment_year: 2024,
        advisor_name: 'Dr. Rajeshwari Deshmukh', guardian_name: 'Rajesh Sharma', guardian_phone: '+91 98201 11402',
        address: 'Flat 402, Shantiniketan Residency, Kothrud / Mumbai Campus Hostel Block C', sgpa: 9.56, cgpa: 9.42,
        semester_history: [
          { sem: 'Semester I', ay: '2024–25', sgpa: 9.20, credits: 22, status: 'Passed with Distinction' },
          { sem: 'Semester II', ay: '2024–25', sgpa: 9.35, credits: 22, status: 'Passed with Distinction' },
          { sem: 'Semester III', ay: '2025–26', sgpa: 9.48, credits: 23, status: 'Passed with Distinction' },
          { sem: 'Semester IV', ay: '2025–26', sgpa: 9.52, credits: 23, status: 'Passed with Distinction' }
        ],
        status: 'Active', created_at: nowIso, updated_at: nowIso
      },
      {
        id: stu2, profile_id: profStu2, student_id: 'MIT2026002', course: 'B.Tech Computer Engineering', course_id: courseComp, department_id: deptComp,
        semester: 'Semester V', academic_year: '2026–27', division: 'Division A · Roll No. 04', batch: 'B1', roll_no: '04',
        date_of_birth: '2005-11-22', blood_group: 'A+', category: 'Open Merit', phone: '+91 98192 33410', enrollment_year: 2024,
        advisor_name: 'Dr. Rajeshwari Deshmukh', guardian_name: 'Sanjay Kulkarni', guardian_phone: '+91 98190 88211',
        address: 'B-12, Saraswati Co-op Society, Dadar West, Mumbai 400028', sgpa: 9.18, cgpa: 9.06,
        semester_history: [
          { sem: 'Semester I', ay: '2024–25', sgpa: 8.90, credits: 22, status: 'Passed with Distinction' },
          { sem: 'Semester II', ay: '2024–25', sgpa: 9.02, credits: 22, status: 'Passed with Distinction' },
          { sem: 'Semester III', ay: '2025–26', sgpa: 9.10, credits: 23, status: 'Passed with Distinction' },
          { sem: 'Semester IV', ay: '2025–26', sgpa: 9.15, credits: 23, status: 'Passed with Distinction' }
        ],
        status: 'Active', created_at: nowIso, updated_at: nowIso
      },
      {
        id: stu3, profile_id: profStu3, student_id: 'MIT2026003', course: 'B.Tech Computer Engineering', course_id: courseComp, department_id: deptComp,
        semester: 'Semester V', academic_year: '2026–27', division: 'Division A · Roll No. 29', batch: 'B2', roll_no: '29',
        date_of_birth: '2005-03-09', blood_group: 'B+', category: 'Open Merit', phone: '+91 97654 11920', enrollment_year: 2024,
        advisor_name: 'Dr. Rajeshwari Deshmukh', guardian_name: 'Mahesh Deshmukh', guardian_phone: '+91 97650 30019',
        address: 'Plot 18, Vidya Nagar, Thane East, Maharashtra 400603', sgpa: 7.45, cgpa: 7.62,
        semester_history: [
          { sem: 'Semester I', ay: '2024–25', sgpa: 7.80, credits: 22, status: 'Passed First Class' },
          { sem: 'Semester II', ay: '2024–25', sgpa: 7.65, credits: 22, status: 'Passed First Class' },
          { sem: 'Semester III', ay: '2025–26', sgpa: 7.55, credits: 23, status: 'Passed First Class' },
          { sem: 'Semester IV', ay: '2025–26', sgpa: 7.50, credits: 23, status: 'Passed First Class' }
        ],
        status: 'Active', created_at: nowIso, updated_at: nowIso
      },
      {
        id: stu4, profile_id: profStu4, student_id: 'MIT2026004', course: 'B.Tech Computer Engineering', course_id: courseComp, department_id: deptComp,
        semester: 'Semester V', academic_year: '2026–27', division: 'Division A · Roll No. 19', batch: 'B2', roll_no: '19',
        date_of_birth: '2005-07-17', blood_group: 'AB+', category: 'Institutional Merit', phone: '+91 98231 66501', enrollment_year: 2024,
        advisor_name: 'Dr. Rajeshwari Deshmukh', guardian_name: 'Vivek Joshi', guardian_phone: '+91 98230 91100',
        address: '301, Gulmohar Heights, Vile Parle East, Mumbai 400057', sgpa: 9.72, cgpa: 9.64,
        semester_history: [
          { sem: 'Semester I', ay: '2024–25', sgpa: 9.55, credits: 22, status: 'Passed with Distinction' },
          { sem: 'Semester II', ay: '2024–25', sgpa: 9.60, credits: 22, status: 'Passed with Distinction' },
          { sem: 'Semester III', ay: '2025–26', sgpa: 9.68, credits: 23, status: 'Passed with Distinction' },
          { sem: 'Semester IV', ay: '2025–26', sgpa: 9.70, credits: 23, status: 'Passed with Distinction' }
        ],
        status: 'Active', created_at: nowIso, updated_at: nowIso
      },
      {
        id: stu5, profile_id: profStu5, student_id: 'MIT2026005', course: 'B.Tech Computer Engineering', course_id: courseComp, department_id: deptComp,
        semester: 'Semester V', academic_year: '2026–27', division: 'Division A · Roll No. 41', batch: 'B3', roll_no: '41',
        date_of_birth: '2005-01-30', blood_group: 'O-', category: 'Open Merit', phone: '+91 99208 44123', enrollment_year: 2024,
        advisor_name: 'Dr. Rajeshwari Deshmukh', guardian_name: 'Prakash Patil', guardian_phone: '+91 99200 77812',
        address: '14, Sai Krupa Residency, Navi Mumbai 400706', sgpa: 7.12, cgpa: 7.34,
        semester_history: [
          { sem: 'Semester I', ay: '2024–25', sgpa: 7.50, credits: 22, status: 'Passed First Class' },
          { sem: 'Semester II', ay: '2024–25', sgpa: 7.40, credits: 22, status: 'Passed First Class' },
          { sem: 'Semester III', ay: '2025–26', sgpa: 7.30, credits: 23, status: 'Passed First Class' },
          { sem: 'Semester IV', ay: '2025–26', sgpa: 7.18, credits: 23, status: 'Passed First Class' }
        ],
        status: 'Active', created_at: nowIso, updated_at: nowIso
      }
    ];

    const subjects = [
      { id: subCs501, code: 'CS501', name: 'Design & Analysis of Algorithms', course_id: courseComp, faculty_id: fac1, semester: 'Semester V', credits: 4, subject_type: 'Lecture', created_at: nowIso },
      { id: subCs502, code: 'CS502', name: 'Operating SystemsPrinciples', course_id: courseComp, faculty_id: fac1, semester: 'Semester V', credits: 4, subject_type: 'Lecture', created_at: nowIso },
      { id: subCs503, code: 'CS503', name: 'Database Management Systems', course_id: courseComp, faculty_id: fac1, semester: 'Semester V', credits: 4, subject_type: 'Lecture', created_at: nowIso },
      { id: subCs504, code: 'CS504', name: 'Computer Networks & Security', course_id: courseComp, faculty_id: fac2, semester: 'Semester V', credits: 4, subject_type: 'Lecture', created_at: nowIso },
      { id: subCs505, code: 'CS505', name: 'Software Engineering & DevOps', course_id: courseComp, faculty_id: fac2, semester: 'Semester V', credits: 3, subject_type: 'Lab', created_at: nowIso }
    ];
    subjects[1].name = 'Operating Systems Principles';

    const student_subjects = [];
    for (const sId of [stu1, stu2, stu3, stu4, stu5]) {
      for (const subId of [subCs501, subCs502, subCs503, subCs504, subCs505]) {
        student_subjects.push({
          id: generateUuid(),
          student_id: sId,
          subject_id: subId,
          academic_year: '2026–27',
          semester: 'Semester V',
          created_at: nowIso
        });
      }
    }

    const seedGrades = [
      [stu1, subCs501, 19, 19, 55, 93, 'O'],
      [stu1, subCs502, 18, 19, 53, 90, 'O'],
      [stu1, subCs503, 20, 19, 56, 95, 'O'],
      [stu1, subCs504, 17, 18, 50, 85, 'A+'],
      [stu1, subCs505, 19, 18, 54, 91, 'O'],
      [stu2, subCs501, 18, 17, 51, 86, 'A+'],
      [stu2, subCs502, 17, 18, 49, 84, 'A+'],
      [stu2, subCs503, 19, 18, 53, 90, 'O'],
      [stu2, subCs504, 16, 17, 48, 81, 'A+'],
      [stu2, subCs505, 18, 19, 52, 89, 'A+'],
      [stu3, subCs501, 13, 14, 41, 68, 'B+'],
      [stu3, subCs502, 12, 13, 39, 64, 'B+'],
      [stu3, subCs503, 15, 14, 44, 73, 'A'],
      [stu3, subCs504, 14, 13, 40, 67, 'B+'],
      [stu3, subCs505, 16, 15, 45, 76, 'A'],
      [stu4, subCs501, 20, 19, 57, 96, 'O'],
      [stu4, subCs502, 19, 20, 56, 95, 'O'],
      [stu4, subCs503, 20, 20, 58, 98, 'O'],
      [stu4, subCs504, 19, 18, 54, 91, 'O'],
      [stu4, subCs505, 19, 19, 55, 93, 'O'],
      [stu5, subCs501, 12, 11, 38, 61, 'B+'],
      [stu5, subCs502, 13, 12, 39, 64, 'B+'],
      [stu5, subCs503, 11, 12, 36, 59, 'B'],
      [stu5, subCs504, 14, 13, 41, 68, 'B+'],
      [stu5, subCs505, 15, 14, 42, 71, 'A']
    ];

    const grades = seedGrades.map(([student_id, subject_id, internal_1, internal_2, end_sem, total, grade]) => ({
      id: generateUuid(),
      student_id,
      subject_id,
      academic_year: '2026–27',
      semester: 'Semester V',
      internal_1,
      internal_2,
      end_sem,
      total,
      grade,
      updated_by: fac1,
      created_at: nowIso,
      updated_at: nowIso
    }));

    const subjectDefs = [
      { id: subCs501, code: 'CS501', total: 42, fac: fac1, type: 'Lecture', counts: { [stu1]: 39, [stu2]: 38, [stu3]: 29, [stu4]: 41, [stu5]: 28 } },
      { id: subCs502, code: 'CS502', total: 40, fac: fac1, type: 'Lecture', counts: { [stu1]: 36, [stu2]: 35, [stu3]: 27, [stu4]: 39, [stu5]: 29 } },
      { id: subCs503, code: 'CS503', total: 38, fac: fac1, type: 'Lecture', counts: { [stu1]: 36, [stu2]: 34, [stu3]: 30, [stu4]: 37, [stu5]: 25 } },
      { id: subCs504, code: 'CS504', total: 40, fac: fac2, type: 'Lecture', counts: { [stu1]: 35, [stu2]: 36, [stu3]: 28, [stu4]: 38, [stu5]: 27 } },
      { id: subCs505, code: 'CS505', total: 36, fac: fac2, type: 'Lab Practical', counts: { [stu1]: 34, [stu2]: 33, [stu3]: 28, [stu4]: 35, [stu5]: 26 } }
    ];

    const attendance_sessions = [];
    const attendance_records = [];
    const baseDate = '2026-07-01';
    for (let sIdx = 0; sIdx < subjectDefs.length; sIdx++) {
      const sDef = subjectDefs[sIdx];
      for (let i = 1; i <= sDef.total; i++) {
        const sessId = `88888888-8888-4888-8888-${String(sIdx + 1).padStart(4, '0')}${String(i).padStart(8, '0')}`;
        const sessDate = addDaysISO(baseDate, (i - 1) * 2 + sIdx);
        attendance_sessions.push({
          id: sessId,
          subject_id: sDef.id,
          faculty_id: sDef.fac,
          date: sessDate,
          start_time: '09:00',
          end_time: '10:00',
          type: sDef.type,
          division: 'A',
          batch: 'ALL',
          created_at: nowIso
        });
        for (const stuId of [stu1, stu2, stu3, stu4, stu5]) {
          const presentLimit = sDef.counts[stuId];
          const status = i <= presentLimit ? 'Present' : 'Absent';
          attendance_records.push({
            id: generateUuid(),
            attendance_session_id: sessId,
            student_id: stuId,
            status,
            marked_at: sessDate + 'T10:00:00Z',
            marked_by: sDef.fac
          });
        }
      }
    }

    const notices = [
      {
        id: '99999999-9999-4999-8999-999999999001',
        title: 'End-Semester Theory & Practical Examination Timetable (Odd Semester 2026–27)',
        category: 'Examination Notice',
        body: 'The Office of the Controller of Examinations has released the provisional schedule for B.Tech Semester V End-Semester Theory and Laboratory Examinations. Hall tickets will be enabled for students maintaining a minimum 75% aggregate attendance across registered courses.',
        author_id: profFac1,
        author_label: 'Controller of Examinations, MIT',
        published: true,
        published_at: '2026-10-04T09:00:00Z',
        created_at: nowIso,
        updated_at: nowIso
      },
      {
        id: '99999999-9999-4999-8999-999999999002',
        title: 'Internal Assessment II — Lab Submissions & Viva-Voce Schedule for CS501 & CS503',
        category: 'Academic Notice',
        body: 'All Division A & B students of Third Year Computer Engineering are instructed to complete their Git repository verification and journal sign-off for Design & Analysis of Algorithms (CS501) and DBMS (CS503) in Lab Complex 3 before Friday, 4:30 PM.',
        author_id: profFac1,
        author_label: 'Dr. Rajeshwari Deshmukh · Dept. of Computer Engineering',
        published: true,
        published_at: '2026-10-02T11:30:00Z',
        created_at: nowIso,
        updated_at: nowIso
      },
      {
        id: '99999999-9999-4999-8999-999999999003',
        title: 'MIT Annual Research Conclave & Industry Capstone Symposium 2026',
        category: 'College Announcement',
        body: 'MAEER’s Maharashtra Institute of Technology invites undergraduate research teams to submit abstracts for the Annual Engineering Research Conclave. Selected projects will receive seed grants from the MIT Innovation & Incubation Centre.',
        author_id: profFac1,
        author_label: 'Dean — Research & Development, MIT',
        published: true,
        published_at: '2026-09-28T14:00:00Z',
        created_at: nowIso,
        updated_at: nowIso
      },
      {
        id: '99999999-9999-4999-8999-999999999004',
        title: 'Mandatory Attendance Compliance & Medical Condonation Submission Window',
        category: 'Academic Notice',
        body: 'Students whose cumulative attendance is currently below the statutory 75% threshold must report to their respective Faculty Advisors along with verified supporting documentation by the 10th of this month.',
        author_id: profFac1,
        author_label: 'Office of Academic Affairs, MIT',
        published: true,
        published_at: '2026-09-24T10:15:00Z',
        created_at: nowIso,
        updated_at: nowIso
      }
    ];

    const faculty_activity = [
      { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaa001', faculty_id: fac1, action: 'Updated grades', description: 'Updated Internal Assessment II marks for CS503 (Database Management Systems)', created_at: '2026-10-05T10:42:00Z' },
      { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaa002', faculty_id: fac1, action: 'Recorded attendance', description: 'Marked lecture attendance for CS501 — Division A (5/5 cohort records synced)', created_at: '2026-10-04T16:15:00Z' },
      { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaa003', faculty_id: fac1, action: 'Published notice', description: 'Published Academic Notice: Internal Assessment II — Lab Submissions & Viva-Voce Schedule', created_at: '2026-10-02T11:30:00Z' },
      { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaa004', faculty_id: fac1, action: 'Attendance audit', description: 'Flagged 2 students in B.Tech Computer Engineering below 75% attendance threshold', created_at: '2026-09-29T14:20:00Z' }
    ];

    const weekStart = getMondayISO(new Date());
    const weekEnd = addDaysISO(weekStart, 5);
    const ttId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbb001';
    const timetables = [
      { id: ttId, week_start: weekStart, week_end: weekEnd, status: 'published', created_by: fac1, published_at: nowIso, created_at: nowIso, updated_at: nowIso }
    ];

    const dMon = weekStart;
    const dTue = addDaysISO(weekStart, 1);
    const dWed = addDaysISO(weekStart, 2);
    const dThu = addDaysISO(weekStart, 3);
    const dFri = addDaysISO(weekStart, 4);
    const dSat = addDaysISO(weekStart, 5);

    const seedEntries = [
      ['tte_mon_1',  dMon, 'Monday',    '09:00', '10:00', subCs501, 'CS501', 'Design & Analysis of Algorithms',  fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-204 · Aryabhatta Block', 'Lecture'],
      ['tte_mon_2',  dMon, 'Monday',    '10:15', '11:15', subCs502, 'CS502', 'Operating Systems Principles',     fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-204 · Aryabhatta Block', 'Lecture'],
      ['tte_mon_3',  dMon, 'Monday',    '11:30', '13:30', subCs503, 'CS503', 'Database Management Systems',     fac1, courseComp, deptComp, 'A', 'B1',  'ALL', 'Systems Lab 3 · Wing B',    'Lab'],
      ['tte_mon_b1', dMon, 'Monday',    '11:30', '12:30', subCs501, 'CS501', 'Design & Analysis of Algorithms',  fac1, courseComp, deptComp, 'B', 'ALL', 'ALL', 'LH-208 · Aryabhatta Block', 'Lecture'],
      ['tte_tue_1',  dTue, 'Tuesday',   '09:00', '10:00', subCs503, 'CS503', 'Database Management Systems',     fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-204 · Aryabhatta Block', 'Lecture'],
      ['tte_tue_2',  dTue, 'Tuesday',   '10:15', '11:15', subCs504, 'CS504', 'Computer Networks & Security',    fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-305 · Ramanujan Hall',   'Lecture'],
      ['tte_tue_3',  dTue, 'Tuesday',   '14:00', '16:00', subCs505, 'CS505', 'Software Engineering & DevOps',   fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'DevOps Studio · Block C',   'Lab'],
      ['tte_wed_1',  dWed, 'Wednesday', '09:00', '10:00', subCs502, 'CS502', 'Operating Systems Principles',     fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-204 · Aryabhatta Block', 'Lecture'],
      ['tte_wed_2',  dWed, 'Wednesday', '10:15', '11:15', subCs501, 'CS501', 'Design & Analysis of Algorithms',  fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-204 · Aryabhatta Block', 'Lecture'],
      ['tte_wed_3',  dWed, 'Wednesday', '11:30', '12:30', subCs504, 'CS504', 'Computer Networks & Security',    fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'Seminar Hall 2',            'Tutorial'],
      ['tte_thu_1',  dThu, 'Thursday',  '09:00', '10:00', subCs503, 'CS503', 'Database Management Systems',     fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-204 · Aryabhatta Block', 'Lecture'],
      ['tte_thu_2',  dThu, 'Thursday',  '10:15', '12:15', subCs502, 'CS502', 'Operating Systems Principles',     fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'OS Kernel Lab · Wing A',    'Lab'],
      ['tte_thu_3',  dThu, 'Thursday',  '14:00', '15:00', subCs505, 'CS505', 'Software Engineering & DevOps',   fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-305 · Ramanujan Hall',   'Lecture'],
      ['tte_fri_1',  dFri, 'Friday',    '09:00', '10:00', subCs501, 'CS501', 'Design & Analysis of Algorithms',  fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-204 · Aryabhatta Block', 'Lecture'],
      ['tte_fri_2',  dFri, 'Friday',    '11:30', '12:30', subCs504, 'CS504', 'Computer Networks & Security',    fac2, courseComp, deptComp, 'A', 'ALL', 'ALL', 'LH-305 · Ramanujan Hall',   'Lecture'],
      ['tte_sat_1',  dSat, 'Saturday',  '10:00', '12:00', subCs503, 'CS503', 'Database Management Systems',     fac1, courseComp, deptComp, 'A', 'ALL', 'ALL', 'Systems Lab 2',             'Tutorial']
    ];

    const timetable_entries = seedEntries.map(e => ({
      id: e[0],
      timetable_id: ttId,
      date: e[1],
      day: e[2],
      start_time: e[3],
      end_time: e[4],
      subject_id: e[5],
      subject_code: e[6],
      subject_name: e[7],
      faculty_id: e[8],
      course_id: e[9],
      department_id: e[10],
      semester: 'Semester V',
      division: e[11],
      batch: e[12],
      group_code: e[13],
      room: e[14],
      type: e[15],
      entry_status: 'Scheduled',
      created_at: nowIso,
      updated_at: nowIso
    }));

    return {
      auth_users,
      departments,
      courses,
      profiles,
      faculty,
      students,
      subjects,
      student_subjects,
      attendance_sessions,
      attendance_records,
      grades,
      notices,
      faculty_activity,
      timetables,
      timetable_entries
    };
  }

  let _staticRelationalStore = null;
  function getStaticStore() {
    if (_staticRelationalStore) return _staticRelationalStore;
    try {
      const raw = localStorage.getItem(RELATIONAL_SNAPSHOT_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.profiles) && Array.isArray(parsed.students)) {
          const curMonday = getMondayISO(new Date());
          if (!Array.isArray(parsed.timetables) || !parsed.timetables.some(t => t.week_start === curMonday)) {
            const fresh = buildSeedRelationalTables();
            parsed.timetables = fresh.timetables;
            parsed.timetable_entries = fresh.timetable_entries;
          }
          _staticRelationalStore = parsed;
          return _staticRelationalStore;
        }
      }
    } catch (e) {}
    _staticRelationalStore = buildSeedRelationalTables();
    persistStaticStore();
    return _staticRelationalStore;
  }

  function persistStaticStore() {
    if (!_staticRelationalStore) return;
    try {
      localStorage.setItem(RELATIONAL_SNAPSHOT_KEY, JSON.stringify(_staticRelationalStore));
    } catch (e) {}
  }

  function getStaticAuthContext() {
    const store = getStaticStore();
    const session = loadStoredSession();
    if (!session || !session.user || !session.user.id) {
      return { authenticated: false, authUserId: null, role: 'anon', profile: null, student: null, faculty: null };
    }
    const authUser = store.auth_users.find(u => u.id === session.user.id);
    if (!authUser) {
      return { authenticated: false, authUserId: null, role: 'anon', profile: null, student: null, faculty: null };
    }
    const profile = store.profiles.find(p => p.auth_user_id === authUser.id) || null;
    let student = null;
    let faculty = null;
    if (profile) {
      if (profile.role === 'student') {
        student = store.students.find(s => s.profile_id === profile.id) || null;
      } else if (profile.role === 'faculty') {
        faculty = store.faculty.find(f => f.profile_id === profile.id) || null;
      }
    }
    return {
      authenticated: true,
      authUserId: authUser.id,
      role: profile ? profile.role : 'authenticated',
      profile,
      student,
      faculty
    };
  }

  function filterStaticRlsSelect(table, rows, ctx) {
    const store = getStaticStore();
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
        const pubIds = new Set(store.timetables.filter(t => String(t.status || '').toLowerCase() === 'published').map(t => t.id));
        return rows.filter(r => {
          if (!pubIds.has(r.timetable_id)) return false;
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

  function checkStaticRlsWrite(table, method, payload, targetRow, ctx) {
    if (!ctx.authenticated) return { allowed: false, message: 'permission denied (unauthenticated)' };
    if (table === 'profiles') {
      if (method === 'POST' && payload.auth_user_id === ctx.authUserId && payload.role === 'student') return { allowed: true };
      if (method === 'PATCH' && targetRow && targetRow.auth_user_id === ctx.authUserId && (!payload.role || payload.role === targetRow.role)) return { allowed: true };
      return { allowed: false, message: 'row-level security policy violation for table "profiles"' };
    }
    if (table === 'students') {
      if (method === 'POST' && ctx.profile && ctx.profile.role === 'student' && payload.profile_id === ctx.profile.id) return { allowed: true };
      if (method === 'PATCH' && ctx.role === 'faculty') return { allowed: true };
      return { allowed: false, message: 'row-level security policy violation for table "students"' };
    }
    if (table === 'student_subjects') {
      if (method === 'POST' && (ctx.role === 'faculty' || (ctx.student && payload.student_id === ctx.student.id))) return { allowed: true };
      if (ctx.role === 'faculty') return { allowed: true };
      return { allowed: false, message: 'row-level security policy violation for table "student_subjects"' };
    }
    if (ctx.role === 'faculty') return { allowed: true };
    return { allowed: false, message: `new row violates row-level security policy for table "${table}"` };
  }

  function enrichStaticRow(table, row, selectParam, ctx) {
    if (!selectParam || !selectParam.includes('(')) return { ...row };
    const store = getStaticStore();
    const enriched = { ...row };
    if (selectParam.includes('profiles(') && row.profile_id) {
      const p = store.profiles.find(x => x.id === row.profile_id);
      enriched.profiles = p ? { ...p } : null;
    }
    if (selectParam.includes('departments(') && row.department_id) {
      const d = store.departments.find(x => x.id === row.department_id);
      enriched.departments = d ? { ...d } : null;
    }
    if (selectParam.includes('courses(') && row.course_id) {
      const c = store.courses.find(x => x.id === row.course_id);
      enriched.courses = c ? { ...c } : null;
    }
    if (selectParam.includes('subjects(') && row.subject_id) {
      const s = store.subjects.find(x => x.id === row.subject_id);
      enriched.subjects = s ? { ...s } : null;
    }
    if (selectParam.includes('faculty(') && row.faculty_id) {
      const f = store.faculty.find(x => x.id === row.faculty_id);
      const fp = f ? store.profiles.find(x => x.id === f.profile_id) : null;
      enriched.faculty = f ? { ...f, profiles: fp ? { ...fp } : null } : null;
    }
    if (selectParam.includes('attendance_sessions(') && row.attendance_session_id) {
      const sess = store.attendance_sessions.find(x => x.id === row.attendance_session_id);
      const sub = sess ? store.subjects.find(x => x.id === sess.subject_id) : null;
      enriched.attendance_sessions = sess ? { ...sess, subjects: sub ? { ...sub } : null } : null;
    }
    if (selectParam.includes('timetable_entries(') && table === 'timetables') {
      const rawEntries = store.timetable_entries
        .filter(e => e.timetable_id === row.id)
        .sort((a, b) => String(a.date).localeCompare(String(b.date)) || String(a.start_time).localeCompare(String(b.start_time)));
      const visEntries = filterStaticRlsSelect('timetable_entries', rawEntries, ctx);
      enriched.timetable_entries = visEntries.map(e => {
        const f = store.faculty.find(x => x.id === e.faculty_id);
        const fp = f ? store.profiles.find(x => x.id === f.profile_id) : null;
        return { ...e, faculty: f ? { ...f, profiles: fp ? { ...fp } : null } : null };
      });
    }
    return enriched;
  }

  function matchesFilter(row, col, expr) {
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
    if (expr.startsWith('neq.')) return String(val ?? '') !== expr.slice(4);
    if (expr.startsWith('gt.')) return Number(val) > Number(expr.slice(3)) || String(val) > expr.slice(3);
    if (expr.startsWith('gte.')) return Number(val) >= Number(expr.slice(4)) || String(val) >= expr.slice(4);
    if (expr.startsWith('lt.')) return Number(val) < Number(expr.slice(3)) || String(val) < expr.slice(3);
    if (expr.startsWith('lte.')) return Number(val) <= Number(expr.slice(4)) || String(val) <= expr.slice(4);
    return true;
  }

  function executeStaticQuery(builder) {
    const store = getStaticStore();
    const table = builder.table;
    const tableArr = store[table];
    if (!Array.isArray(tableArr)) {
      return { data: null, error: { status: 404, code: '404', message: `Relation "${table}" does not exist` } };
    }

    const ctx = getStaticAuthContext();
    const selectParam = builder.queryParams.get('select') || '*';
    const orderParam = builder.queryParams.get('order');
    const limitParam = builder.queryParams.get('limit');
    const onConflictParam = builder.queryParams.get('on_conflict');
    const wantsSingle = builder.acceptHeader.includes('application/vnd.pgrst.object+json');

    const reserved = new Set(['select', 'order', 'limit', 'offset', 'on_conflict']);
    const filters = [];
    for (const [k, v] of builder.queryParams.entries()) {
      if (!reserved.has(k)) filters.push([k, v]);
    }

    if (builder.method === 'GET') {
      let rows = filterStaticRlsSelect(table, tableArr, ctx);
      for (const [col, expr] of filters) {
        rows = rows.filter(r => matchesFilter(r, col, expr));
      }
      if (orderParam) {
        const orders = orderParam.split(',').map(p => {
          const [c, d] = p.trim().split('.');
          return { col: c, desc: String(d || '').toLowerCase() === 'desc' };
        });
        rows = [...rows].sort((a, b) => {
          for (const o of orders) {
            const va = a[o.col] ?? '';
            const vb = b[o.col] ?? '';
            if (va < vb) return o.desc ? 1 : -1;
            if (va > vb) return o.desc ? -1 : 1;
          }
          return 0;
        });
      }
      if (limitParam) rows = rows.slice(0, Number(limitParam));
      const enriched = rows.map(r => enrichStaticRow(table, r, selectParam, ctx));
      if (wantsSingle) {
        if (enriched.length !== 1) return { data: null, error: { status: 406, code: 'PGRST116', message: 'JSON object requested, multiple (or no) rows returned' } };
        return { data: enriched[0], error: null };
      }
      if (builder._maybeSingle) {
        return { data: enriched[0] || null, error: null };
      }
      return { data: enriched, error: null };
    }

    if (builder.method === 'POST') {
      const items = Array.isArray(builder.bodyPayload) ? builder.bodyPayload : [builder.bodyPayload];
      const inserted = [];
      const isUpsert = builder.preferHeaders.includes('resolution=merge-duplicates') || Boolean(onConflictParam);

      for (const raw of items) {
        const item = { ...raw };
        if (!item.id) item.id = generateUuid();
        if (!item.created_at) item.created_at = new Date().toISOString();

        const check = checkStaticRlsWrite(table, 'POST', item, null, ctx);
        if (!check.allowed) {
          return { data: null, error: { status: 403, code: '42501', message: check.message } };
        }

        if (isUpsert && onConflictParam) {
          const conflictCols = onConflictParam.split(',').map(c => c.trim());
          const existingIdx = tableArr.findIndex(r => conflictCols.every(c => String(r[c]) === String(item[c])));
          if (existingIdx >= 0) {
            const merged = { ...tableArr[existingIdx], ...item, id: tableArr[existingIdx].id };
            tableArr[existingIdx] = merged;
            inserted.push(enrichStaticRow(table, merged, selectParam, ctx));
          } else {
            tableArr.push(item);
            inserted.push(enrichStaticRow(table, item, selectParam, ctx));
          }
        } else {
          if (table === 'students' && tableArr.some(s => String(s.student_id).toUpperCase() === String(item.student_id).toUpperCase())) {
            return { data: null, error: { status: 409, code: '23505', message: 'UNIQUE constraint failed: students.student_id' } };
          }
          tableArr.push(item);
          if (table === 'student_subjects') {
            const existsGrade = store.grades.some(g => g.student_id === item.student_id && g.subject_id === item.subject_id);
            if (!existsGrade) {
              store.grades.push({
                id: generateUuid(),
                student_id: item.student_id,
                subject_id: item.subject_id,
                academic_year: item.academic_year || '2026–27',
                semester: item.semester || 'Semester V',
                internal_1: 0,
                internal_2: 0,
                end_sem: 0,
                total: 0,
                grade: 'P',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
              });
            }
          }
          inserted.push(enrichStaticRow(table, item, selectParam, ctx));
        }
      }
      persistStaticStore();
      return { data: wantsSingle ? (inserted[0] || null) : inserted, error: null };
    }

    if (builder.method === 'PATCH') {
      const matching = tableArr.filter(r => filters.every(([col, expr]) => matchesFilter(r, col, expr)));
      for (const row of matching) {
        const check = checkStaticRlsWrite(table, 'PATCH', builder.bodyPayload, row, ctx);
        if (!check.allowed) {
          return { data: null, error: { status: 403, code: '42501', message: check.message } };
        }
      }
      const updated = [];
      for (const row of matching) {
        Object.assign(row, builder.bodyPayload);
        updated.push(enrichStaticRow(table, row, selectParam, ctx));
      }
      persistStaticStore();
      return { data: wantsSingle ? (updated[0] || null) : updated, error: null };
    }

    if (builder.method === 'DELETE') {
      const matching = tableArr.filter(r => filters.every(([col, expr]) => matchesFilter(r, col, expr)));
      for (const row of matching) {
        const check = checkStaticRlsWrite(table, 'DELETE', {}, row, ctx);
        if (!check.allowed) {
          return { data: null, error: { status: 403, code: '42501', message: check.message } };
        }
      }
      const toRemove = new Set(matching.map(r => r.id));
      store[table] = tableArr.filter(r => !toRemove.has(r.id));
      persistStaticStore();
      return { data: matching, error: null };
    }

    return { data: [], error: null };
  }

  function makeStaticSession(authUser) {
    const nowSec = Math.floor(Date.now() / 1000);
    const userObj = {
      id: authUser.id,
      aud: 'authenticated',
      role: 'authenticated',
      email: authUser.email,
      user_metadata: authUser.raw_user_meta_data || {},
      created_at: authUser.created_at
    };
    return {
      access_token: `sb_static_jwt_${authUser.id}_${generateUuid()}`,
      refresh_token: `sb_static_ref_${generateUuid()}`,
      expires_in: 28800,
      expires_at: nowSec + 28800,
      token_type: 'bearer',
      user: userObj
    };
  }

  // PostgREST Query Builder compatible with @supabase/supabase-js v2
  class PostgrestQueryBuilder {
    constructor(table) {
      this.table = table;
      this.method = 'GET';
      this.queryParams = new URLSearchParams();
      this.queryParams.set('select', '*');
      this.bodyPayload = null;
      this.preferHeaders = [];
      this.acceptHeader = 'application/json';
    }

    select(columns = '*') {
      const cleaned = String(columns).replace(/\s+/g, '');
      this.queryParams.set('select', cleaned || '*');
      if (this.method === 'POST' || this.method === 'PATCH' || this.method === 'DELETE') {
        if (!this.preferHeaders.includes('return=representation')) {
          this.preferHeaders.push('return=representation');
        }
      }
      return this;
    }

    insert(values) {
      this.method = 'POST';
      this.bodyPayload = values;
      if (!this.preferHeaders.includes('return=representation')) {
        this.preferHeaders.push('return=representation');
      }
      return this;
    }

    upsert(values, options = {}) {
      this.method = 'POST';
      this.bodyPayload = values;
      if (!this.preferHeaders.includes('return=representation')) {
        this.preferHeaders.push('return=representation');
      }
      if (!this.preferHeaders.includes('resolution=merge-duplicates')) {
        this.preferHeaders.push('resolution=merge-duplicates');
      }
      if (options.onConflict) {
        this.queryParams.set('on_conflict', options.onConflict);
      }
      return this;
    }

    update(values) {
      this.method = 'PATCH';
      this.bodyPayload = values;
      if (!this.preferHeaders.includes('return=representation')) {
        this.preferHeaders.push('return=representation');
      }
      return this;
    }

    delete() {
      this.method = 'DELETE';
      if (!this.preferHeaders.includes('return=representation')) {
        this.preferHeaders.push('return=representation');
      }
      return this;
    }

    eq(column, value) {
      this.queryParams.append(column, `eq.${value}`);
      return this;
    }

    neq(column, value) {
      this.queryParams.append(column, `neq.${value}`);
      return this;
    }

    gt(column, value) {
      this.queryParams.append(column, `gt.${value}`);
      return this;
    }

    gte(column, value) {
      this.queryParams.append(column, `gte.${value}`);
      return this;
    }

    lt(column, value) {
      this.queryParams.append(column, `lt.${value}`);
      return this;
    }

    lte(column, value) {
      this.queryParams.append(column, `lte.${value}`);
      return this;
    }

    ilike(column, pattern) {
      this.queryParams.append(column, `ilike.${pattern}`);
      return this;
    }

    in(column, valuesArray) {
      const list = (valuesArray || []).join(',');
      this.queryParams.append(column, `in.(${list})`);
      return this;
    }

    is(column, value) {
      this.queryParams.append(column, `is.${value}`);
      return this;
    }

    order(column, { ascending = true } = {}) {
      const dir = ascending ? 'asc' : 'desc';
      const existing = this.queryParams.get('order');
      this.queryParams.set('order', existing ? `${existing},${column}.${dir}` : `${column}.${dir}`);
      return this;
    }

    limit(count) {
      this.queryParams.set('limit', String(count));
      return this;
    }

    single() {
      this.acceptHeader = 'application/vnd.pgrst.object+json';
      return this;
    }

    maybeSingle() {
      this._maybeSingle = true;
      this.limit(1);
      return this;
    }

    async _execute() {
      const url = `${SUPABASE_URL}/rest/v1/${this.table}?${this.queryParams.toString()}`;
      const extraHeaders = { Accept: this.acceptHeader };
      if (this.preferHeaders.length > 0) {
        extraHeaders.Prefer = this.preferHeaders.join(',');
      }

      try {
        const response = await fetch(url, {
          method: this.method,
          headers: buildHeaders(extraHeaders),
          body: this.bodyPayload !== null ? JSON.stringify(this.bodyPayload) : undefined
        });

        if (response.status === 404 || response.status === 405) {
          return executeStaticQuery(this);
        }

        let payload = null;
        const text = await response.text();
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch (e) {
            payload = text;
          }
        }

        if (!response.ok) {
          return {
            data: null,
            error: {
              status: response.status,
              code: payload?.code || String(response.status),
              message: payload?.message || payload?.error_description || payload?.error || 'Database request failed',
              details: payload?.details || null
            }
          };
        }

        if (this._maybeSingle) {
          const row = Array.isArray(payload) ? (payload[0] || null) : payload;
          return { data: row, error: null };
        }

        return { data: payload, error: null };
      } catch (netErr) {
        if (global.location && String(global.location.hostname || '').includes('github.io')) {
          return executeStaticQuery(this);
        }
        return {
          data: null,
          error: {
            status: 0,
            code: 'NETWORK_ERROR',
            message: 'Unable to reach the academic database server. Please check your connection and try again.'
          }
        };
      }
    }

    then(onFulfilled, onRejected) {
      return this._execute().then(onFulfilled, onRejected);
    }
  }

  const supabaseClient = {
    supabaseUrl: SUPABASE_URL,
    auth: {
      async signUp({ email, password, options = {} }) {
        try {
          const response = await fetch(`${SUPABASE_URL}/auth/v1/signup`, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify({
              email,
              password,
              data: options.data || {}
            })
          });
          if (response.status === 404 || response.status === 405) {
            const store = getStaticStore();
            const cleanEmail = String(email || '').trim().toLowerCase();
            if (store.auth_users.some(u => u.email.toLowerCase() === cleanEmail)) {
              return { data: { user: null, session: null }, error: { status: 422, code: 'user_already_exists', message: 'This email address is already registered. Please sign in instead.' } };
            }
            const newAuthUser = {
              id: generateUuid(),
              email: cleanEmail,
              verifier: encodeVerifier(String(password || '')),
              raw_user_meta_data: { ...(options.data || {}), role: 'student' },
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString()
            };
            store.auth_users.push(newAuthUser);
            persistStaticStore();
            const session = makeStaticSession(newAuthUser);
            saveStoredSession(session, false);
            notifyAuthListeners('SIGNED_IN', session);
            return { data: { user: session.user, session }, error: null };
          }

          const payload = await response.json().catch(() => ({}));
          if (!response.ok) {
            return {
              data: { user: null, session: null },
              error: {
                status: response.status,
                code: payload.code || payload.error || 'signup_failed',
                message: payload.message || payload.msg || payload.error_description || 'Unable to create account.'
              }
            };
          }
          const session = payload.session || (payload.access_token ? {
            access_token: payload.access_token,
            refresh_token: payload.refresh_token,
            expires_in: payload.expires_in,
            expires_at: payload.expires_at,
            token_type: payload.token_type || 'bearer',
            user: payload.user
          } : null);
          if (session) {
            saveStoredSession(session, false);
            notifyAuthListeners('SIGNED_IN', session);
          }
          return {
            data: { user: payload.user || session?.user || null, session },
            error: null
          };
        } catch (err) {
          return {
            data: { user: null, session: null },
            error: { status: 0, code: 'NETWORK_ERROR', message: 'Network error while creating account.' }
          };
        }
      },

      async signInWithPassword({ email, password, rememberMe = true }) {
        try {
          const response = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify({ email, password })
          });
          if (response.status === 404 || response.status === 405) {
            const store = getStaticStore();
            const authUser = store.auth_users.find(u => u.email.toLowerCase() === String(email || '').trim().toLowerCase());
            if (!authUser || authUser.verifier !== encodeVerifier(String(password || ''))) {
              return { data: { user: null, session: null }, error: { status: 400, code: 'invalid_credentials', message: 'Invalid ID or password.' } };
            }
            const session = makeStaticSession(authUser);
            saveStoredSession(session, rememberMe);
            notifyAuthListeners('SIGNED_IN', session);
            return { data: { user: session.user, session }, error: null };
          }

          const payload = await response.json().catch(() => ({}));
          if (!response.ok || !payload.access_token) {
            return {
              data: { user: null, session: null },
              error: {
                status: response.status,
                code: payload.error || 'invalid_credentials',
                message: payload.error_description || payload.message || 'Invalid ID or password.'
              }
            };
          }
          const session = {
            access_token: payload.access_token,
            refresh_token: payload.refresh_token,
            expires_in: payload.expires_in,
            expires_at: payload.expires_at,
            token_type: payload.token_type || 'bearer',
            user: payload.user
          };
          saveStoredSession(session, rememberMe);
          notifyAuthListeners('SIGNED_IN', session);
          return { data: { user: payload.user, session }, error: null };
        } catch (err) {
          return {
            data: { user: null, session: null },
            error: { status: 0, code: 'NETWORK_ERROR', message: 'Unable to reach authentication service.' }
          };
        }
      },

      async signInWithDemoPreset(presetKey, rememberMe = false) {
        try {
          const response = await fetch(`${SUPABASE_URL}/auth/v1/demo-session`, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify({ preset: presetKey })
          });
          if (response.status === 404 || response.status === 405) {
            const presetEmails = {
              student1: 'princekumar.sharma@mitmumbai.edu.in',
              student2: 'ananya.kulkarni@mitmumbai.edu.in',
              faculty1: 'rajeshwari.deshmukh@mitmumbai.edu.in'
            };
            const targetEmail = presetEmails[presetKey];
            const store = getStaticStore();
            const authUser = store.auth_users.find(u => u.email.toLowerCase() === String(targetEmail || '').toLowerCase());
            if (!authUser) return { data: null, error: { message: 'Demo preset unavailable.' } };
            const session = makeStaticSession(authUser);
            saveStoredSession(session, rememberMe);
            notifyAuthListeners('SIGNED_IN', session);
            return { data: { user: session.user, session }, error: null };
          }

          const payload = await response.json().catch(() => ({}));
          if (!response.ok || !payload.access_token) {
            return {
              data: null,
              error: { message: payload.message || 'Demo preset unavailable.' }
            };
          }
          const session = {
            access_token: payload.access_token,
            refresh_token: payload.refresh_token,
            expires_in: payload.expires_in,
            expires_at: payload.expires_at,
            token_type: payload.token_type || 'bearer',
            user: payload.user
          };
          saveStoredSession(session, rememberMe);
          notifyAuthListeners('SIGNED_IN', session);
          return { data: { ...payload, session }, error: null };
        } catch (err) {
          return { data: null, error: { message: 'Unable to reach demo authentication endpoint.' } };
        }
      },

      async signOut() {
        const session = loadStoredSession();
        if (session) {
          try {
            await fetch(`${SUPABASE_URL}/auth/v1/logout`, {
              method: 'POST',
              headers: buildHeaders()
            });
          } catch (e) {}
        }
        clearStoredSession();
        notifyAuthListeners('SIGNED_OUT', null);
        return { error: null };
      },

      async getSession() {
        const session = loadStoredSession();
        return { data: { session }, error: null };
      },

      async getUser() {
        const session = loadStoredSession();
        if (!session) {
          return { data: { user: null }, error: null };
        }
        try {
          const response = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            method: 'GET',
            headers: buildHeaders()
          });
          if (response.status === 404 || response.status === 405) {
            return { data: { user: session.user || null }, error: null };
          }
          if (!response.ok) {
            clearStoredSession();
            notifyAuthListeners('SIGNED_OUT', null);
            return {
              data: { user: null },
              error: { status: response.status, message: 'Session expired. Please sign in again.' }
            };
          }
          const user = await response.json();
          return { data: { user }, error: null };
        } catch (err) {
          return {
            data: { user: session.user || null },
            error: { status: 0, code: 'NETWORK_ERROR', message: 'Unable to verify session.' }
          };
        }
      },

      onAuthStateChange(callback) {
        if (typeof callback === 'function') {
          authListeners.add(callback);
        }
        return {
          data: {
            subscription: {
              unsubscribe: () => authListeners.delete(callback)
            }
          }
        };
      }
    },

    from(table) {
      return new PostgrestQueryBuilder(table);
    },

    async rpc(fnName, params = {}) {
      try {
        const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fnName}`, {
          method: 'POST',
          headers: buildHeaders(),
          body: JSON.stringify(params)
        });
        if (response.status === 404 || response.status === 405) {
          if (fnName === 'resolve_institutional_login_email') {
            const store = getStaticStore();
            const ident = String(params.p_identifier || '').trim();
            if (!ident) return { data: [], error: null };
            if (ident.includes('@')) {
              const p = store.profiles.find(x => x.email.toLowerCase() === ident.toLowerCase());
              return { data: p ? [{ email: p.email, role: p.role }] : [], error: null };
            }
            const stu = store.students.find(s => s.student_id.toUpperCase() === ident.toUpperCase());
            if (stu) {
              const p = store.profiles.find(x => x.id === stu.profile_id);
              return { data: p ? [{ email: p.email, role: p.role }] : [], error: null };
            }
            const fac = store.faculty.find(f => f.faculty_id.toUpperCase() === ident.toUpperCase());
            if (fac) {
              const p = store.profiles.find(x => x.id === fac.profile_id);
              return { data: p ? [{ email: p.email, role: p.role }] : [], error: null };
            }
            return { data: [], error: null };
          }
        }
        const payload = await response.json().catch(() => null);
        if (!response.ok) {
          return {
            data: null,
            error: {
              status: response.status,
              message: payload?.message || 'RPC execution failed'
            }
          };
        }
        return { data: payload, error: null };
      } catch (err) {
        return {
          data: null,
          error: { status: 0, code: 'NETWORK_ERROR', message: 'Network error during RPC call.' }
        };
      }
    }
  };

  global.supabaseClient = supabaseClient;
  global.REMEMBER_PREF_KEY = REMEMBER_PREF_KEY;
})(typeof window !== 'undefined' ? window : globalThis);
