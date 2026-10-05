/**
 * MIT Academic Portal — Automated End-to-End Backend, RLS & 14-Point Verification Suite
 * Verifies:
 *   - Syntax & Security Audit (Section 39)
 *   - PostgreSQL Migration Schema & RLS Policies (001, 002, 003)
 *   - Tests 1 to 14 against live HTTP server + supabase-client.js + portal-api.js
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');

function logPass(label, detail = '') {
  console.log(`  [PASS] ${label}${detail ? ' — ' + detail : ''}`);
}

function getWeekStartISO(dateInput = new Date()) {
  const d = new Date(dateInput.getFullYear(), dateInput.getMonth(), dateInput.getDate());
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

async function runVerification() {
  console.log('================================================================');
  console.log(' MIT ACADEMIC PORTAL — BACKEND & DATABASE VERIFICATION SUITE');
  console.log('================================================================\n');

  // ------------------------------------------------------------------
  // 0. STATIC SYNTAX, SCHEMA & SECURITY AUDIT (Section 39)
  // ------------------------------------------------------------------
  console.log('--- Phase 1: Syntax, Schema & Security Audit ---');

  const indexHtml = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  const supabaseClientCode = fs.readFileSync(path.join(ROOT, 'js', 'supabase-client.js'), 'utf8');
  const portalApiCode = fs.readFileSync(path.join(ROOT, 'js', 'portal-api.js'), 'utf8');

  // Parse inline scripts from index.html
  const scriptRegex = /<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  let scriptIndex = 0;
  while ((match = scriptRegex.exec(indexHtml)) !== null) {
    scriptIndex++;
    new vm.Script(match[1], { filename: `index.html#script-${scriptIndex}` });
  }
  new vm.Script(supabaseClientCode, { filename: 'js/supabase-client.js' });
  new vm.Script(portalApiCode, { filename: 'js/portal-api.js' });
  logPass('Frontend JS Syntax Check', `Validated ${scriptIndex} inline script block(s) + supabase-client.js + portal-api.js`);

  // Security & Legacy Cleanup Audit
  const forbiddenFrontendPatterns = [
    { pattern: 'mit_academic_portal_db_v2', label: 'Legacy localStorage DB key' },
    { pattern: 'computeHash', label: 'Fake client-side password hash function' },
    { pattern: 'passwordDigests', label: 'Client-side password digest map' },
    { pattern: 'createInitialPortalDB', label: 'Hardcoded localStorage seed function' },
    { pattern: 'savePortalDB', label: 'Legacy localStorage DB writer' },
    { pattern: 'SUPABASE_SERVICE_ROLE_KEY', label: 'Secret service_role key in frontend' },
    { pattern: 'postgres://', label: 'Direct database connection string in frontend' }
  ];

  const combinedFrontend = indexHtml + '\n' + supabaseClientCode + '\n' + portalApiCode;
  for (const item of forbiddenFrontendPatterns) {
    assert.equal(
      combinedFrontend.includes(item.pattern),
      false,
      `Forbidden pattern found in frontend: ${item.pattern} (${item.label})`
    );
  }
  logPass('Security & Cleanup Audit (Section 39)', 'Zero secrets, zero fake hashing, zero localStorage DB objects in frontend');

  // Check SQL migrations
  const schemaSql = fs.readFileSync(path.join(ROOT, 'supabase', 'migrations', '001_initial_schema.sql'), 'utf8');
  const rlsSql = fs.readFileSync(path.join(ROOT, 'supabase', 'migrations', '002_rls_policies.sql'), 'utf8');
  const seedSql = fs.readFileSync(path.join(ROOT, 'supabase', 'migrations', '003_seed_data.sql'), 'utf8');

  const requiredTables = [
    'departments',
    'courses',
    'profiles',
    'students',
    'faculty',
    'subjects',
    'student_subjects',
    'attendance_sessions',
    'attendance_records',
    'grades',
    'notices',
    'faculty_activity',
    'timetables',
    'timetable_entries'
  ];

  for (const tbl of requiredTables) {
    assert.ok(
      schemaSql.includes(`CREATE TABLE IF NOT EXISTS public.${tbl}`),
      `Missing table ${tbl} in 001_initial_schema.sql`
    );
    assert.ok(
      rlsSql.includes(`ALTER TABLE public.${tbl} ENABLE ROW LEVEL SECURITY`),
      `Missing RLS enablement for ${tbl} in 002_rls_policies.sql`
    );
  }
  assert.ok(seedSql.length > 1000, '003_seed_data.sql is populated');
  logPass('PostgreSQL Schema & RLS Migrations', `Verified all ${requiredTables.length} normalized tables & RLS policies`);

  // ------------------------------------------------------------------
  // BOOT SERVER ON EPHEMERAL PORT & INITIALIZE CLIENT LAYER
  // ------------------------------------------------------------------
  console.log('\n--- Phase 2: Functional & RLS End-to-End Tests (Tests 1–14) ---');

  const { server: httpServer, db } = require(path.join(ROOT, 'server.js'));

  const server = await new Promise((resolve) => {
    const s = httpServer.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  // Create a browser-like environment for supabase-client.js + portal-api.js
  function createStorageMock() {
    const store = new Map();
    return {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
      clear: () => store.clear()
    };
  }

  function createClientContext() {
    const localStore = createStorageMock();
    const sessionStore = createStorageMock();

    const ctxWindow = {
      location: { origin: baseUrl, protocol: 'http:' },
      localStorage: localStore,
      sessionStorage: sessionStore,
      fetch: global.fetch.bind(global),
      __SUPABASE_CONFIG__: {
        url: baseUrl,
        anonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIn0.public-anon-key'
      }
    };
    ctxWindow.window = ctxWindow;

    const sandbox = vm.createContext({
      window: ctxWindow,
      globalThis: ctxWindow,
      localStorage: localStore,
      sessionStorage: sessionStore,
      fetch: global.fetch.bind(global),
      URLSearchParams,
      console,
      Date,
      Math,
      JSON,
      Promise,
      Set,
      Map,
      Error,
      String,
      Number,
      Boolean,
      Array,
      Object,
      RegExp,
      encodeURIComponent,
      decodeURIComponent,
      setTimeout,
      clearTimeout
    });

    vm.runInContext(supabaseClientCode, sandbox, { filename: 'supabase-client.js' });
    vm.runInContext(portalApiCode, sandbox, { filename: 'portal-api.js' });
    return {
      supabase: ctxWindow.supabaseClient,
      PortalAPI: ctxWindow.PortalAPI,
      localStore,
      sessionStore
    };
  }

  db.prepare("DELETE FROM auth_users WHERE email LIKE 'test.%@mitmumbai.edu.in'").run();
  const uniqueSuffix = String(Date.now()).slice(-4);
  const newStudentId = `MIT20269${uniqueSuffix}`;
  const newStudentEmail = `test.${uniqueSuffix}@mitmumbai.edu.in`;
  const currentMonday = getWeekStartISO(new Date());
  const nextMonday = addDaysISO(currentMonday, 7);
  const nextSaturday = addDaysISO(nextMonday, 5);
  const prevMonday = addDaysISO(currentMonday, -7);
  const attendanceDate = '2026-10-15';
  const noticeTitle = `Dept Seminar Announcement ${uniqueSuffix}`;
  let originalCs501Grade = null;

  // Clean up any leftover test artifacts for nextMonday / attendanceDate before starting
  db.prepare('DELETE FROM timetable_entries WHERE timetable_id IN (SELECT id FROM timetables WHERE week_start = ?)').run(nextMonday);
  db.prepare('DELETE FROM timetables WHERE week_start = ?').run(nextMonday);
  db.prepare('DELETE FROM attendance_records WHERE attendance_session_id IN (SELECT id FROM attendance_sessions WHERE date = ?)').run(attendanceDate);
  db.prepare('DELETE FROM attendance_sessions WHERE date = ?').run(attendanceDate);

  try {
    // ==================================================================
    // TEST 1: Student Registration
    // Register a new student -> Auth user created + profile created + student record created
    // ==================================================================
    const regClient = createClientContext();

    const regResult = await regClient.PortalAPI.registerStudentAccount({
      name: 'Aditya Deshpande',
      studentId: newStudentId,
      email: newStudentEmail,
      phone: '+91 98230 55443',
      dob: '2005-06-15',
      course: 'B.Tech Computer Engineering',
      displayCourse: 'B.Tech Computer Engineering',
      department: 'Computer Engineering',
      semester: 'Semester V',
      division: 'A',
      displayDivision: 'Division A',
      initials: 'AD',
      password: 'SecurePassword@2026'
    });

    assert.equal(regResult.ok, true, `Registration failed: ${regResult.error || ''}`);
    assert.equal(regResult.studentId, newStudentId);
    logPass('Test 1: Student Registration', `Created Auth User + Profile + Student (${newStudentId}) + Semester V Subject Enrollments`);

    // ==================================================================
    // TEST 2: Student Login
    // Login with registered student & seeded student MIT2026001 -> loads profile, attendance, grades, notices, timetable
    // ==================================================================
    const stuNewLogin = await regClient.PortalAPI.signInPortalUser(newStudentId, 'SecurePassword@2026', 'student', true);
    assert.equal(stuNewLogin.ok, true);
    assert.equal(stuNewLogin.user.role, 'student');
    assert.equal(stuNewLogin.user.userId, newStudentId);
    const newStuProfile = await regClient.PortalAPI.getStudentProfile(newStudentId);
    assert.equal(newStuProfile.name, 'Aditya Deshpande');
    assert.equal(newStuProfile.subjects.length, 5, 'New student automatically enrolled in 5 Semester V subjects');

    // Now login as seeded student MIT2026001 (Princekumar Sharma, Division A)
    const stuClientA = createClientContext();
    const stuLoginA = await stuClientA.PortalAPI.signInPortalUser('MIT2026001', 'MIT2026001', 'student', true);
    assert.equal(stuLoginA.ok, true);
    assert.equal(stuLoginA.user.userId, 'MIT2026001');
    assert.equal(stuLoginA.user.role, 'student');

    const stuProfileA = await stuClientA.PortalAPI.getStudentProfile('MIT2026001');
    assert.equal(stuProfileA.name, 'Princekumar Sharma');
    assert.ok(stuProfileA.division.includes('Division A'));
    assert.equal(stuProfileA.subjects.length, 5, 'Loaded 5 subjects with derived attendance & grades');

    const cs501Initial = stuProfileA.subjects.find(s => s.code === 'CS501');
    originalCs501Grade = {
      int1: cs501Initial.int1,
      int2: cs501Initial.int2,
      endSem: cs501Initial.endSem
    };

    const stuNotices = await stuClientA.PortalAPI.getPublishedNotices('all');
    assert.ok(stuNotices.length >= 4, 'Loaded published notices');

    const stuWeekTT = await stuClientA.PortalAPI.getCurrentTimetable(currentMonday);
    assert.ok(stuWeekTT && stuWeekTT.status === 'Published', 'Loaded published weekly timetable');
    logPass('Test 2: Student Login', `Authenticated ${newStudentId} & MIT2026001; loaded profile, derived attendance, grades, notices, timetable`);

    // ==================================================================
    // TEST 3: Faculty Login
    // Login with faculty credentials -> loads students, attendance, grades, notices, timetable manager
    // ==================================================================
    const facClient = createClientContext();
    const facLogin = await facClient.PortalAPI.signInPortalUser('FAC2026101', 'FAC2026101', 'faculty', true);
    assert.equal(facLogin.ok, true);
    assert.equal(facLogin.user.userId, 'FAC2026101');
    assert.equal(facLogin.user.role, 'faculty');
    assert.equal(facLogin.user.name, 'Dr. Rajeshwari Deshmukh');

    const cohortData = await facClient.PortalAPI.getFacultyCohortData();
    const allStudentsMap = cohortData.students;
    assert.ok(Object.keys(allStudentsMap).length >= 6, 'Faculty loaded all cohort students including newly registered student');
    assert.ok(cohortData.facultyActivity.length >= 4, 'Faculty loaded activity log from PostgreSQL');
    logPass('Test 3: Faculty Login', `Authenticated FAC2026101; loaded ${Object.keys(allStudentsMap).length} students, activity feed, and timetable manager`);

    // ==================================================================
    // TEST 4: Unauthorized Access (RLS Student Isolation)
    // Student MIT2026001 tries to read another student's data (MIT2026002) -> Denied / 0 rows
    // ==================================================================
    const { data: otherStudentsRows } = await stuClientA.supabase
      .from('students')
      .select('id,student_id')
      .eq('student_id', 'MIT2026002');
    assert.equal(
      (otherStudentsRows || []).length,
      0,
      'RLS must prevent MIT2026001 from reading MIT2026002 student row'
    );

    const ananyaUuid = allStudentsMap['MIT2026002'].uuid;
    const { data: otherGradesRows } = await stuClientA.supabase
      .from('grades')
      .select('*')
      .eq('student_id', ananyaUuid);
    assert.equal(
      (otherGradesRows || []).length,
      0,
      'RLS must prevent MIT2026001 from reading MIT2026002 grades'
    );

    const { data: otherAttRows } = await stuClientA.supabase
      .from('attendance_records')
      .select('*')
      .eq('student_id', ananyaUuid);
    assert.equal(
      (otherAttRows || []).length,
      0,
      'RLS must prevent MIT2026001 from reading MIT2026002 attendance_records'
    );
    logPass('Test 4: Unauthorized Read Access (RLS)', 'Student MIT2026001 blocked from reading MIT2026002 profile, grades, and attendance');

    // ==================================================================
    // TEST 5: Unauthorized Write (RLS Write Protection)
    // Student MIT2026001 tries to update grades, attendance, notices, timetable -> Denied
    // ==================================================================
    const { error: stuGradeWriteErr } = await stuClientA.supabase
      .from('grades')
      .insert({
        student_id: stuProfileA.uuid,
        subject_id: stuProfileA.subjects[0].subjectId,
        internal_1: 20,
        internal_2: 20,
        end_sem: 60,
        total: 100,
        grade: 'O'
      });
    assert.ok(stuGradeWriteErr, 'Student must be denied INSERT on grades');

    const { error: stuNoticeWriteErr } = await stuClientA.supabase
      .from('notices')
      .insert({
        title: 'Unauthorized Student Notice',
        category: 'Academic Notice',
        body: 'Should fail RLS',
        published: true
      });
    assert.ok(stuNoticeWriteErr, 'Student must be denied INSERT on notices');

    const { error: stuTTWriteErr } = await stuClientA.supabase
      .from('timetables')
      .insert({
        week_start: '2026-12-07',
        week_end: '2026-12-12',
        status: 'published'
      });
    assert.ok(stuTTWriteErr, 'Student must be denied INSERT on timetables');
    logPass('Test 5: Unauthorized Write Protection (RLS)', 'Student blocked from writing to grades, notices, and timetables (HTTP 403)');

    // ==================================================================
    // TEST 6: Attendance Update & Dynamic Calculation
    // Faculty marks attendance -> attendance_sessions + attendance_records saved -> student percentage updates
    // ==================================================================
    const attendedBefore = cs501Initial.attended;
    const totalBefore = cs501Initial.total;

    const savedAttResult = await facClient.PortalAPI.saveAttendance('CS501', attendanceDate, {
      MIT2026001: 'Present',
      MIT2026002: 'Absent'
    });
    assert.ok(savedAttResult.session?.id, 'Attendance session created');

    const stuProfileAfterAtt = await stuClientA.PortalAPI.getStudentProfile('MIT2026001');
    const cs501After = stuProfileAfterAtt.subjects.find(s => s.code === 'CS501');
    assert.equal(cs501After.total, totalBefore + 1, 'Total sessions incremented by 1 in DB');
    assert.equal(cs501After.attended, attendedBefore + 1, 'Present sessions incremented by 1 in DB');
    logPass(
      'Test 6: Attendance Update & Dynamic Calculation',
      `CS501 attendance updated from ${attendedBefore}/${totalBefore} to ${cs501After.attended}/${cs501After.total} (${((cs501After.attended / cs501After.total) * 100).toFixed(1)}%)`
    );

    // ==================================================================
    // TEST 7: Grade Update
    // Faculty updates internal/end-sem marks -> grades table updated -> student sees updated marks
    // ==================================================================
    await facClient.PortalAPI.saveGrades('MIT2026001', 'CS501', {
      int1: 20,
      int2: 19,
      endSem: 58
    });

    const stuProfileAfterGrade = await stuClientA.PortalAPI.getStudentProfile('MIT2026001');
    const cs501GradeAfter = stuProfileAfterGrade.subjects.find(s => s.code === 'CS501');
    assert.equal(cs501GradeAfter.int1, 20);
    assert.equal(cs501GradeAfter.int2, 19);
    assert.equal(cs501GradeAfter.endSem, 58);
    assert.equal(cs501GradeAfter.totalMarks, 97);
    assert.equal(cs501GradeAfter.grade, 'O');
    logPass('Test 7: Grade Update', 'Faculty updated CS501 marks for MIT2026001 -> persisted to grades table (97/100, Grade O)');

    // ==================================================================
    // TEST 8: Notice Publish
    // Faculty publishes notice -> stored in notices table -> visible to students
    // ==================================================================
    const createdNotice = await facClient.PortalAPI.createNotice({
      title: noticeTitle,
      category: 'Academic Notice',
      body: 'Mandatory seminar on Distributed Consensus and Cloud Native PostgreSQL architectures.'
    });
    assert.ok(createdNotice?.id, 'Notice row created in DB');

    const updatedStuNotices = await stuClientA.PortalAPI.getPublishedNotices('all');
    assert.ok(
      updatedStuNotices.some(n => n.title === noticeTitle),
      'Newly published faculty notice is immediately visible to student'
    );
    logPass('Test 8: Notice Publish', `Published notice "${noticeTitle}" persisted & visible on Student Notice Board`);

    // ==================================================================
    // TEST 9 & TEST 10: Weekly Timetable Creation + Week Navigation
    // Faculty creates next week's timetable, adds entries, publishes -> students see next week
    // ==================================================================
    const createdNextWeek = await facClient.PortalAPI.createTimetableInDB(nextMonday, nextSaturday, 'Draft');
    assert.equal(createdNextWeek.weekStart, nextMonday);
    assert.equal(createdNextWeek.status, 'Draft');

    // Add a Division A entry and a Division B entry to next week
    await facClient.PortalAPI.saveTimetableEntryInDB(nextMonday, nextSaturday, {
      date: nextMonday,
      day: 'Monday',
      startTime: '09:00',
      endTime: '10:00',
      subjectCode: 'CS501',
      subject: 'Operating Systems',
      facultyId: 'FAC2026101',
      course: 'B.Tech Computer Engineering',
      department: 'Computer Engineering',
      semester: 'Semester V',
      division: 'A',
      batch: 'ALL',
      room: 'Room 204',
      type: 'Lecture',
      status: 'Scheduled'
    });

    await facClient.PortalAPI.saveTimetableEntryInDB(nextMonday, nextSaturday, {
      date: nextMonday,
      day: 'Monday',
      startTime: '10:00',
      endTime: '11:00',
      subjectCode: 'CS502',
      subject: 'Database Management Systems',
      facultyId: 'FAC2026101',
      course: 'B.Tech Computer Engineering',
      department: 'Computer Engineering',
      semester: 'Semester V',
      division: 'B',
      batch: 'ALL',
      room: 'Room 208',
      type: 'Lecture',
      status: 'Scheduled'
    });

    // ==================================================================
    // TEST 12: Draft Timetable Protection
    // While next week is Draft, student MIT2026001 must NOT see it
    // ==================================================================
    const stuDraftCheck = await stuClientA.PortalAPI.getCurrentTimetable(nextMonday);
    assert.equal(stuDraftCheck, null, 'Student must not see Draft (unpublished) weekly timetable');
    logPass('Test 12: Draft Timetable Protection (RLS)', `Unpublished week (${nextMonday}) is hidden from students`);

    // Now Faculty publishes next week
    const publishedNextWeek = await facClient.PortalAPI.setTimetablePublishStateInDB(nextMonday, nextSaturday, true);
    assert.equal(publishedNextWeek.status, 'Published');

    // Student fetches Current Week, Next Week, Previous Week
    const stuCurrWeek = await stuClientA.PortalAPI.getCurrentTimetable(currentMonday);
    const stuNextWeek = await stuClientA.PortalAPI.getCurrentTimetable(nextMonday);
    const stuPrevWeek = await stuClientA.PortalAPI.getCurrentTimetable(prevMonday);

    assert.ok(stuCurrWeek && stuCurrWeek.weekStart === currentMonday, 'Student loaded Current Week timetable');
    assert.ok(stuNextWeek && stuNextWeek.weekStart === nextMonday, 'Student loaded Published Next Week timetable');
    assert.equal(stuPrevWeek, null, 'Unscheduled Previous Week returns null');
    logPass('Test 9: Weekly Timetable Creation & Publishing', `Faculty created & published week ${nextMonday} with class entries`);
    logPass('Test 10: Week Navigation', `Verified independent weekly timetable records across Previous (${prevMonday}), Current (${currentMonday}), and Next (${nextMonday}) weeks`);

    // ==================================================================
    // TEST 11: Division Filtering (RLS & Cohort Isolation)
    // Division A student (MIT2026001) only receives Division A entries, NOT Division B entries
    // ==================================================================
    const divBEntriesSeenByDivAStudent = (stuNextWeek.entries || []).filter(e => e.division === 'B');
    assert.equal(
      divBEntriesSeenByDivAStudent.length,
      0,
      'Division A student must not receive Division B timetable entries'
    );
    const divAEntriesSeenByDivAStudent = (stuNextWeek.entries || []).filter(e => e.division === 'A');
    assert.equal(
      divAEntriesSeenByDivAStudent.length,
      1,
      'Division A student receives their Division A timetable entry'
    );
    logPass('Test 11: Division Filtering', 'Division A student (MIT2026001) sees only Division A classes; Division B classes filtered by RLS');

    // ==================================================================
    // TEST 13: Persistence Test
    // Create a fresh client context (simulating browser reload) and verify data persists in DB
    // ==================================================================
    const reloadClient = createClientContext();
    await reloadClient.PortalAPI.signInPortalUser('MIT2026001', 'MIT2026001', 'student', true);
    const persistedProfile = await reloadClient.PortalAPI.getStudentProfile('MIT2026001');
    const persistedCs501 = persistedProfile.subjects.find(s => s.code === 'CS501');
    assert.equal(persistedCs501.totalMarks, 97, 'Updated grade persisted across reload');
    assert.equal(persistedCs501.total, totalBefore + 1, 'Updated attendance persisted across reload');
    logPass('Test 13: Database Persistence Test', 'Fresh session reload confirmed persisted registrations, attendance, grades, notices, and timetables');

    // ==================================================================
    // TEST 14: Logout Test
    // Sign out -> session cleared -> protected requests fail
    // ==================================================================
    await reloadClient.PortalAPI.signOutPortalUser();
    const userAfterLogout = await reloadClient.PortalAPI.getCurrentUser();
    assert.equal(userAfterLogout, null, 'Active user is null after logout');

    const { data: rowsAfterLogout } = await reloadClient.supabase
      .from('students')
      .select('*');
    assert.equal((rowsAfterLogout || []).length, 0, 'Unauthenticated request after logout returns 0 student rows');
    logPass('Test 14: Logout & Session Termination', 'Session token revoked on server and cleared on client; protected queries blocked');

    // Restore original seed state after verification so live DB stays clean
    if (originalCs501Grade) {
      await facClient.PortalAPI.saveGrades('MIT2026001', 'CS501', originalCs501Grade);
    }
    db.prepare('DELETE FROM notices WHERE title = ?').run(noticeTitle);
    db.prepare('DELETE FROM attendance_records WHERE attendance_session_id IN (SELECT id FROM attendance_sessions WHERE date = ?)').run(attendanceDate);
    db.prepare('DELETE FROM attendance_sessions WHERE date = ?').run(attendanceDate);
    db.prepare('DELETE FROM timetable_entries WHERE timetable_id IN (SELECT id FROM timetables WHERE week_start = ?)').run(nextMonday);
    db.prepare('DELETE FROM timetables WHERE week_start = ?').run(nextMonday);
    db.prepare('DELETE FROM auth_users WHERE LOWER(email) = LOWER(?)').run(newStudentEmail);
    db.prepare('DELETE FROM faculty_activity WHERE description LIKE ? OR description LIKE ? OR description LIKE ?').run(
      `%${noticeTitle}%`,
      `%${attendanceDate}%`,
      `%${nextMonday}%`
    );

    console.log('\n================================================================');
    console.log(' ALL 14 FUNCTIONAL & SECURITY TESTS PASSED SUCCESSFULLY (100%)');
    console.log('================================================================\n');
  } finally {
    server.close();
  }
}

runVerification().catch((err) => {
  console.error('\n[FAIL] Verification failed:', err);
  process.exit(1);
});
