/**
 * ============================================================================
 * MIT ACADEMIC PORTAL — FRONTEND DATA-ACCESS LAYER (PostgreSQL via Supabase)
 * File: js/portal-api.js
 *
 * Separates all Supabase Auth & PostgreSQL queries from UI rendering.
 * Enforces:
 * - Single source of truth in Supabase PostgreSQL
 * - Derived attendance percentage calculation (present_sessions / total_sessions * 100)
 * - Clean user-facing error messages (never exposing raw SQL errors)
 * ============================================================================
 */
(function (global) {
  'use strict';

  const sb = global.supabaseClient;

  // Format date strings like "2005-08-14" -> "14 August 2005"
  function formatLongDate(isoStr) {
    if (!isoStr) return '—';
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(isoStr));
    if (!m) return String(isoStr);
    const months = [
      'January', 'February', 'March', 'April', 'May', 'June',
      'July', 'August', 'September', 'October', 'November', 'December'
    ];
    const year = m[1];
    const monthName = months[Number(m[2]) - 1] || m[2];
    const day = String(Number(m[3])).padStart(2, '0');
    return `${day} ${monthName} ${year}`;
  }

  // Format notice date like "04 Oct 2026"
  function formatShortNoticeDate(isoStr) {
    if (!isoStr) return '';
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return String(isoStr);
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const day = String(d.getDate()).padStart(2, '0');
    return `${day} ${months[d.getMonth()]} ${d.getFullYear()}`;
  }

  function formatActivityTimestamp(isoStr) {
    if (!isoStr) return 'Recently';
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return String(isoStr);
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    if (diffMs >= 0 && diffMs < 5 * 60 * 1000) {
      return 'Just now';
    }
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const day = String(d.getDate()).padStart(2, '0');
    const hh = d.getHours();
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ampm = hh >= 12 ? 'PM' : 'AM';
    const h12 = hh % 12 === 0 ? 12 : hh % 12;
    return `${day} ${months[d.getMonth()]} ${d.getFullYear()}, ${String(h12).padStart(2, '0')}:${mm} ${ampm}`;
  }

  function computeLetterGrade(totalScore) {
    const score = Number(totalScore || 0);
    if (score >= 90) return 'O';
    if (score >= 80) return 'A+';
    if (score >= 70) return 'A';
    if (score >= 60) return 'B+';
    if (score >= 50) return 'B';
    if (score >= 40) return 'P';
    return 'F';
  }

  function sanitizeUserFacingError(error, fallbackMsg = 'Unable to complete your request. Please try again.') {
    if (!error) return fallbackMsg;
    const msg = String(error.message || '');
    if (error.code === '42501' || error.status === 403 || msg.includes('row-level security')) {
      return 'Permission denied: Your account is not authorized to perform this action.';
    }
    if (error.code === '23505' || error.status === 409 || msg.includes('UNIQUE')) {
      return 'A record with this identifier or email already exists.';
    }
    if (error.code === 'NETWORK_ERROR' || error.status === 0) {
      return 'Network error: Unable to connect to the MIT Academic Database. Please try again.';
    }
    if (msg.toLowerCase().includes('invalid login credentials') || msg.toLowerCase().includes('invalid id or password')) {
      return 'Invalid ID or password.';
    }
    return fallbackMsg;
  }

  // ==========================================================================
  // 1. AUTHENTICATION & SESSION MANAGEMENT
  // ==========================================================================

  /**
   * Resolves the currently authenticated Supabase user + profile + student/faculty record.
   * Never trusts client-side role overrides; role comes strictly from `profiles` table via RLS.
   */
  async function getCurrentUser() {
    const { data: sessionData } = await sb.auth.getSession();
    if (!sessionData || !sessionData.session) {
      return null;
    }

    const { data: userData, error: userErr } = await sb.auth.getUser();
    if (userErr || !userData || !userData.user) {
      return null;
    }

    const authUser = userData.user;
    const { data: profile, error: profErr } = await sb
      .from('profiles')
      .select('*,departments(*)')
      .eq('auth_user_id', authUser.id)
      .maybeSingle();

    if (profErr || !profile) {
      return null;
    }

    if (profile.role === 'student') {
      const { data: stuRow } = await sb
        .from('students')
        .select('*,departments(*),courses(*)')
        .eq('profile_id', profile.id)
        .maybeSingle();

      return {
        authUserId: authUser.id,
        profileId: profile.id,
        studentUuid: stuRow ? stuRow.id : null,
        userId: stuRow ? stuRow.student_id : profile.email,
        role: 'student',
        name: profile.name,
        email: profile.email,
        initials: profile.initials,
        department: profile.departments?.name || 'Computer Engineering',
        profile,
        studentRecord: stuRow || null
      };
    }

    if (profile.role === 'faculty') {
      const { data: facRow } = await sb
        .from('faculty')
        .select('*,departments(*)')
        .eq('profile_id', profile.id)
        .maybeSingle();

      return {
        authUserId: authUser.id,
        profileId: profile.id,
        facultyUuid: facRow ? facRow.id : null,
        userId: facRow ? facRow.faculty_id : profile.email,
        role: 'faculty',
        name: profile.name,
        email: profile.email,
        initials: profile.initials,
        designation: facRow?.designation || 'Associate Professor',
        department: facRow?.departments?.name || profile.departments?.name || 'Computer Engineering',
        profile,
        facultyRecord: facRow || null
      };
    }

    return null;
  }

  /**
   * Authenticates a student or faculty member via Supabase Auth (email + password).
   * Supports entering either Institute ID (MIT2026001 / FAC2026101) or institutional email.
   */
  async function signInPortalUser(identifier, password, expectedRole, rememberMe = false) {
    const cleanId = String(identifier || '').trim();
    let emailToUse = cleanId;

    if (!cleanId.includes('@')) {
      const { data: resolved, error: rpcErr } = await sb.rpc('resolve_institutional_login_email', {
        p_identifier: cleanId
      });
      if (rpcErr) {
        return { ok: false, error: sanitizeUserFacingError(rpcErr, 'Unable to verify your institute ID. Please try again.') };
      }
      if (!resolved || !resolved.length || !resolved[0].email) {
        return { ok: false, error: 'Invalid ID or password.' };
      }
      emailToUse = resolved[0].email;
    }

    const { data, error } = await sb.auth.signInWithPassword({
      email: emailToUse,
      password,
      rememberMe
    });

    if (error || !data || !data.user) {
      return { ok: false, error: 'Invalid ID or password.' };
    }

    const currentUser = await getCurrentUser();
    if (!currentUser) {
      await sb.auth.signOut();
      return { ok: false, error: 'Unable to load your institutional profile. Please contact the MIT ERP Cell.' };
    }

    if (expectedRole && currentUser.role !== expectedRole) {
      await sb.auth.signOut();
      return { ok: false, error: 'This account does not have access to the selected portal.' };
    }

    return { ok: true, user: currentUser };
  }

  async function signOutPortalUser() {
    await sb.auth.signOut();
    return { ok: true };
  }

  /**
   * Registers a new student account:
   * 1. Checks uniqueness of Student ID & Email
   * 2. Creates Supabase Auth user (email + password)
   * 3. Creates `profiles` row with role = 'student'
   * 4. Creates `students` row with academic details
   * 5. Creates `student_subjects` enrollments for matching course/semester
   */
  async function registerStudentAccount(regInput) {
    const normalizedStudentId = String(regInput.studentId || '').trim().toUpperCase();
    const normalizedEmail = String(regInput.email || '').trim().toLowerCase();

    // Pre-check if Student ID or Email already exists via RPC
    const { data: idLookup } = await sb.rpc('resolve_institutional_login_email', {
      p_identifier: normalizedStudentId
    });
    if (idLookup && idLookup.length > 0) {
      return {
        ok: false,
        field: 'student-id',
        error: 'This Student ID is already registered. Please sign in instead.'
      };
    }

    const { data: emailLookup } = await sb.rpc('resolve_institutional_login_email', {
      p_identifier: normalizedEmail
    });
    if (emailLookup && emailLookup.length > 0) {
      return {
        ok: false,
        field: 'email',
        error: 'This email address is already registered. Please sign in instead.'
      };
    }

    // 1. Resolve Department & Course IDs from PostgreSQL catalog
    const { data: depts } = await sb.from('departments').select('*');
    const { data: courses } = await sb.from('courses').select('*');

    const matchedDept = (depts || []).find(d =>
      d.name.toLowerCase() === regInput.department.toLowerCase() ||
      regInput.department.toLowerCase().includes(d.name.toLowerCase())
    ) || (depts || [])[0];

    const matchedCourse = (courses || []).find(c =>
      c.name.toLowerCase() === regInput.course.toLowerCase() ||
      c.department_id === matchedDept?.id
    ) || (courses || [])[0];

    // 2. Create Supabase Auth User
    const { data: authData, error: signUpErr } = await sb.auth.signUp({
      email: normalizedEmail,
      password: regInput.password,
      options: {
        data: {
          role: 'student',
          student_id: normalizedStudentId,
          name: regInput.name
        }
      }
    });

    if (signUpErr || !authData?.user) {
      const isDupEmail = String(signUpErr?.code || '').includes('exists') || String(signUpErr?.message || '').toLowerCase().includes('already registered');
      return {
        ok: false,
        field: isDupEmail ? 'email' : null,
        error: isDupEmail
          ? 'This email address is already registered. Please sign in instead.'
          : sanitizeUserFacingError(signUpErr, 'Unable to create student account. Please try again.')
      };
    }

    const authUserId = authData.user.id;

    // 3. Create Profile record (role = 'student' enforced by RLS)
    const { data: createdProfiles, error: profErr } = await sb
      .from('profiles')
      .insert({
        auth_user_id: authUserId,
        role: 'student',
        name: regInput.name,
        email: normalizedEmail,
        initials: regInput.initials || 'ST',
        phone: regInput.phone,
        department_id: matchedDept ? matchedDept.id : null
      })
      .select('*');

    const profileRow = Array.isArray(createdProfiles) ? createdProfiles[0] : createdProfiles;
    if (profErr || !profileRow) {
      await sb.auth.signOut();
      return {
        ok: false,
        error: sanitizeUserFacingError(profErr, 'Unable to create student profile record.')
      };
    }

    // 4. Create Student record in `students` table (no fake academic metrics or personal defaults)
    const currentYear = new Date().getFullYear();
    const { data: createdStudents, error: stuErr } = await sb
      .from('students')
      .insert({
        profile_id: profileRow.id,
        student_id: normalizedStudentId,
        course: regInput.displayCourse,
        course_id: matchedCourse ? matchedCourse.id : null,
        department_id: matchedDept ? matchedDept.id : null,
        semester: regInput.semester,
        academic_year: '2026–27',
        division: regInput.displayDivision,
        batch: regInput.batch || 'B1',
        date_of_birth: regInput.dob,
        blood_group: regInput.bloodGroup || null,
        category: regInput.category || null,
        phone: regInput.phone,
        enrollment_year: currentYear,
        advisor_name: regInput.advisor || null,
        guardian_name: regInput.guardianName || null,
        guardian_phone: regInput.guardianPhone || null,
        address: regInput.address || null,
        sgpa: 0,
        cgpa: 0,
        semester_history: [],
        status: 'Active'
      })
      .select('*');

    const studentRow = Array.isArray(createdStudents) ? createdStudents[0] : createdStudents;
    if (stuErr || !studentRow) {
      await sb.auth.signOut();
      const isDupId = String(stuErr?.code || '') === '23505';
      return {
        ok: false,
        field: isDupId ? 'student-id' : null,
        error: isDupId
          ? 'This Student ID is already registered. Please sign in instead.'
          : sanitizeUserFacingError(stuErr, 'Unable to save student enrollment record.')
      };
    }

    // 5. Enroll student in current semester subjects (`student_subjects`)
    const { data: allSubjects } = await sb.from('subjects').select('*');
    if (allSubjects && allSubjects.length > 0) {
      const enrollments = allSubjects.map(sub => ({
        student_id: studentRow.id,
        subject_id: sub.id,
        academic_year: '2026–27',
        semester: regInput.semester
      }));
      await sb.from('student_subjects').insert(enrollments);
    }

    // Sign out after registration so student signs in cleanly via Student Login
    await sb.auth.signOut();

    return {
      ok: true,
      studentId: normalizedStudentId,
      name: regInput.name,
      initials: regInput.initials
    };
  }

  // ==========================================================================
  // 2. STUDENT PROFILE, ATTENDANCE & GRADES DATA LAYER
  // ==========================================================================

  /**
   * Calculates subject-wise and overall attendance from real `attendance_records`
   * and `attendance_sessions` in PostgreSQL:
   *   attendance percentage = present_sessions / total_sessions * 100
   */
  async function getStudentAttendance(studentUuid) {
    const [enrollRes, recordsRes, subjectsRes] = await Promise.all([
      sb.from('student_subjects').select('*,subjects(*)').eq('student_id', studentUuid),
      sb.from('attendance_records').select('*,attendance_sessions(*)').eq('student_id', studentUuid),
      sb.from('subjects').select('*').order('code', { ascending: true })
    ]);

    if (recordsRes.error) {
      throw new Error(sanitizeUserFacingError(recordsRes.error, 'Unable to load your attendance. Please try again.'));
    }

    const subjectsMap = new Map();
    (subjectsRes.data || []).forEach(s => subjectsMap.set(s.id, s));

    const enrolledSubjects = (enrollRes.data || [])
      .map(e => e.subjects || subjectsMap.get(e.subject_id))
      .filter(Boolean)
      .sort((a, b) => String(a.code).localeCompare(String(b.code)));

    const activeSubjects = enrolledSubjects.length > 0 ? enrolledSubjects : (subjectsRes.data || []);
    const records = recordsRes.data || [];

    // Group attendance records by subject_id
    const statsBySubjectId = new Map();
    activeSubjects.forEach(sub => {
      statsBySubjectId.set(sub.id, { attended: 0, total: 0 });
    });

    const historyItems = [];

    records.forEach(rec => {
      const sess = rec.attendance_sessions;
      if (!sess) return;
      const sub = sess.subjects || subjectsMap.get(sess.subject_id);
      if (!sub) return;

      if (!statsBySubjectId.has(sub.id)) {
        statsBySubjectId.set(sub.id, { attended: 0, total: 0 });
      }
      const stat = statsBySubjectId.get(sub.id);
      stat.total += 1;
      if (rec.status === 'Present' || rec.status === 'Late' || rec.status === 'Excused') {
        stat.attended += 1;
      }

      historyItems.push({
        id: rec.id,
        sessionId: sess.id,
        date: sess.date,
        code: sub.code,
        subject: sub.name,
        type: sess.type || 'Lecture',
        status: rec.status,
        markedAt: rec.marked_at
      });
    });

    // Sort history newest first
    historyItems.sort((a, b) => {
      const dCmp = String(b.date || '').localeCompare(String(a.date || ''));
      if (dCmp !== 0) return dCmp;
      return String(b.markedAt || '').localeCompare(String(a.markedAt || ''));
    });

    // Build subject attendance summary array
    let totalAttendedAll = 0;
    let totalSessionsAll = 0;

    const subjectAttendance = activeSubjects.map(sub => {
      const st = statsBySubjectId.get(sub.id) || { attended: 0, total: 0 };
      totalAttendedAll += st.attended;
      totalSessionsAll += st.total;
      const pct = st.total > 0 ? Number(((st.attended / st.total) * 100).toFixed(1)) : 0;
      return {
        subjectId: sub.id,
        code: sub.code,
        name: sub.name,
        credits: sub.credits,
        attended: st.attended,
        total: st.total,
        percentage: pct
      };
    });

    const overallPercentage = totalSessionsAll > 0
      ? Number(((totalAttendedAll / totalSessionsAll) * 100).toFixed(1))
      : 0;

    return {
      overallPercentage,
      totalAttended: totalAttendedAll,
      totalSessions: totalSessionsAll,
      subjectAttendance,
      attendanceHistory: historyItems.slice(0, 12)
    };
  }

  /**
   * Retrieves student grades from PostgreSQL `grades` table joined with `subjects`.
   */
  async function getStudentGrades(studentUuid) {
    const { data, error } = await sb
      .from('grades')
      .select('*,subjects(*)')
      .eq('student_id', studentUuid);

    if (error) {
      throw new Error(sanitizeUserFacingError(error, 'Unable to load your academic grades. Please try again.'));
    }

    const gradesList = (data || [])
      .map(g => ({
        id: g.id,
        subjectId: g.subject_id,
        code: g.subjects?.code || '',
        name: g.subjects?.name || '',
        credits: Number(g.subjects?.credits || 4),
        int1: Number(g.internal_1 || 0),
        int2: Number(g.internal_2 || 0),
        endSem: Number(g.end_sem || 0),
        total: Number(g.total || (Number(g.internal_1 || 0) + Number(g.internal_2 || 0) + Number(g.end_sem || 0))),
        grade: g.grade || computeLetterGrade(g.total)
      }))
      .sort((a, b) => String(a.code).localeCompare(String(b.code)));

    return gradesList;
  }

  /**
   * Retrieves the complete normalized Student Profile + derived Attendance + Grades
   * for the currently authenticated student (or specified student when called by Faculty).
   */
  async function getStudentProfile(studentCodeOrUuid = null) {
    let query = sb.from('students').select('*,profiles(*),departments(*),courses(*)');
    if (studentCodeOrUuid) {
      if (String(studentCodeOrUuid).includes('-') && String(studentCodeOrUuid).length > 20) {
        query = query.eq('id', studentCodeOrUuid);
      } else {
        query = query.eq('student_id', String(studentCodeOrUuid).toUpperCase());
      }
    }

    const { data: stuRow, error: stuErr } = await query.maybeSingle();
    if (stuErr || !stuRow) {
      throw new Error(sanitizeUserFacingError(stuErr, 'Unable to load student profile from database.'));
    }

    const [attData, gradesList] = await Promise.all([
      getStudentAttendance(stuRow.id),
      getStudentGrades(stuRow.id)
    ]);

    const gradesByCode = new Map();
    gradesList.forEach(g => gradesByCode.set(g.code, g));

    const combinedSubjects = attData.subjectAttendance.map(subAtt => {
      const g = gradesByCode.get(subAtt.code);
      return {
        subjectId: subAtt.subjectId,
        code: subAtt.code,
        name: subAtt.name,
        credits: subAtt.credits,
        attended: subAtt.attended,
        total: subAtt.total,
        percentage: subAtt.percentage,
        int1: g ? g.int1 : 0,
        int2: g ? g.int2 : 0,
        endSem: g ? g.endSem : 0,
        totalMarks: g ? g.total : 0,
        grade: g ? g.grade : '—',
        hasGrade: Boolean(g)
      };
    });

    const profileObj = stuRow.profiles || {};
    const deptObj = stuRow.departments || {};
    const courseObj = stuRow.courses || {};

    return {
      uuid: stuRow.id,
      profileId: stuRow.profile_id,
      id: stuRow.student_id,
      name: profileObj.name || 'Student',
      initials: profileObj.initials || 'ST',
      email: profileObj.email || '',
      phone: stuRow.phone || profileObj.phone || '—',
      course: stuRow.course || courseObj.name || 'B.Tech Computer Engineering',
      courseId: stuRow.course_id,
      department: deptObj.name || 'Computer Engineering',
      departmentId: stuRow.department_id,
      semester: stuRow.semester || 'Semester V',
      academicYear: stuRow.academic_year || '2026–27',
      division: stuRow.division || 'Division A',
      batch: stuRow.batch || 'B1',
      dob: formatLongDate(stuRow.date_of_birth),
      dateOfBirth: stuRow.date_of_birth,
      bloodGroup: stuRow.blood_group || '—',
      category: stuRow.category || '—',
      admissionYear: String(stuRow.enrollment_year || new Date().getFullYear()),
      advisor: stuRow.advisor_name || '—',
      guardianName: stuRow.guardian_name || '—',
      guardianPhone: stuRow.guardian_phone || '—',
      address: stuRow.address || '—',
      sgpa: stuRow.sgpa !== null && stuRow.sgpa !== undefined ? Number(stuRow.sgpa) : 0,
      cgpa: stuRow.cgpa !== null && stuRow.cgpa !== undefined ? Number(stuRow.cgpa) : 0,
      semesterHistory: Array.isArray(stuRow.semester_history) ? stuRow.semester_history : [],
      status: stuRow.status || 'Active',
      subjects: combinedSubjects,
      attendanceHistory: attData.attendanceHistory,
      overallAttendancePct: attData.overallPercentage
    };
  }

  // ==========================================================================
  // 3. NOTICES DATA LAYER
  // ==========================================================================

  async function getPublishedNotices(categoryFilter = 'all') {
    let query = sb
      .from('notices')
      .select('*')
      .eq('published', true)
      .order('published_at', { ascending: false });

    if (categoryFilter && categoryFilter !== 'all') {
      query = query.eq('category', categoryFilter);
    }

    const { data, error } = await query;
    if (error) {
      throw new Error(sanitizeUserFacingError(error, 'Unable to load institutional notices.'));
    }

    return (data || []).map(n => ({
      id: n.id,
      title: n.title,
      category: n.category,
      date: formatShortNoticeDate(n.published_at || n.created_at),
      author: n.author_label || 'Office of Academic Affairs, MIT',
      body: n.body,
      published: Boolean(n.published),
      publishedAt: n.published_at
    }));
  }

  async function createNotice({ title, category, body }) {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only authorized faculty can publish notices.');
    }

    const authorLabel = `${user.name} · Dept. of ${user.department || 'Computer Engineering'}`;
    const nowIso = new Date().toISOString();

    const { data, error } = await sb
      .from('notices')
      .insert({
        title: String(title || '').trim(),
        category: String(category || 'Academic Notice').trim(),
        body: String(body || '').trim(),
        author_id: user.profileId,
        author_label: authorLabel,
        published: true,
        published_at: nowIso
      })
      .select('*')
      .single();

    if (error) {
      throw new Error(sanitizeUserFacingError(error, 'Unable to publish notice.'));
    }

    if (user.facultyUuid) {
      await logFacultyActivity(
        user.facultyUuid,
        'Published notice',
        `Published new ${category}: ${title}`
      );
    }

    return data;
  }

  async function updateNotice(noticeId, { title, category, body, published = true }) {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only authorized faculty can update notices.');
    }

    const { data, error } = await sb
      .from('notices')
      .update({
        title: String(title || '').trim(),
        category: String(category || 'Academic Notice').trim(),
        body: String(body || '').trim(),
        published: Boolean(published),
        updated_at: new Date().toISOString()
      })
      .eq('id', noticeId)
      .select('*')
      .single();

    if (error) {
      throw new Error(sanitizeUserFacingError(error, 'Unable to update notice.'));
    }

    if (user.facultyUuid) {
      await logFacultyActivity(
        user.facultyUuid,
        'Updated notice',
        `Edited notice: ${title}`
      );
    }

    return data;
  }

  async function deleteNoticeRecord(noticeId, noticeTitle = '') {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only authorized faculty can delete notices.');
    }

    const { error } = await sb.from('notices').delete().eq('id', noticeId);
    if (error) {
      throw new Error(sanitizeUserFacingError(error, 'Unable to delete notice.'));
    }

    if (user.facultyUuid) {
      await logFacultyActivity(
        user.facultyUuid,
        'Removed notice',
        `Removed notice: ${noticeTitle || noticeId}`
      );
    }

    return true;
  }

  // ==========================================================================
  // 4. FACULTY COHORT, ATTENDANCE & GRADES MUTATIONS
  // ==========================================================================

  async function logFacultyActivity(facultyUuid, action, description) {
    if (!facultyUuid) return null;
    const { data } = await sb
      .from('faculty_activity')
      .insert({
        faculty_id: facultyUuid,
        action: String(action || 'Academic update'),
        description: String(description || ''),
        created_at: new Date().toISOString()
      })
      .select('*');
    return data;
  }

  /**
   * Queries Supabase for all students joined with their profiles, departments, courses,
   * attendance records, and grades. Used by Faculty Student Directory, Attendance Register,
   * and Marks & Grade Sheet.
   */
  async function getStudents() {
    const [
      studentsRes,
      subjectsRes,
      attRecordsRes,
      gradesRes
    ] = await Promise.all([
      sb.from('students').select('*,profiles(*),departments(*),courses(*)').order('student_id', { ascending: true }),
      sb.from('subjects').select('*').order('code', { ascending: true }),
      sb.from('attendance_records').select('*,attendance_sessions(*)'),
      sb.from('grades').select('*')
    ]);

    if (studentsRes.error) {
      throw new Error(sanitizeUserFacingError(studentsRes.error, 'Unable to load student directory. Please try again.'));
    }

    const allSubjects = subjectsRes.data || [];
    const subjectsById = new Map(allSubjects.map(s => [s.id, s]));
    const allGrades = gradesRes.data || [];
    const allAttRecords = attRecordsRes.data || [];

    const studentsList = [];
    const studentsMap = {};

    (studentsRes.data || []).forEach(stuRow => {
      const stuAttRecords = allAttRecords.filter(r => r.student_id === stuRow.id);
      const stuGrades = allGrades.filter(g => g.student_id === stuRow.id);

      const subjectsForStu = allSubjects.map(sub => {
        const subAtt = stuAttRecords.filter(r => r.attendance_sessions && r.attendance_sessions.subject_id === sub.id);
        const total = subAtt.length;
        const attended = subAtt.filter(r => r.status === 'Present' || r.status === 'Late' || r.status === 'Excused').length;
        const gRow = stuGrades.find(g => g.subject_id === sub.id);

        return {
          subjectId: sub.id,
          code: sub.code,
          name: sub.name,
          credits: sub.credits,
          attended,
          total,
          int1: gRow ? Number(gRow.internal_1 || 0) : 0,
          int2: gRow ? Number(gRow.internal_2 || 0) : 0,
          endSem: gRow ? Number(gRow.end_sem || 0) : 0,
          grade: gRow ? (gRow.grade || computeLetterGrade(gRow.total)) : '—',
          hasGrade: Boolean(gRow)
        };
      });

      const historyItems = stuAttRecords
        .filter(r => r.attendance_sessions)
        .map(r => {
          const sess = r.attendance_sessions;
          const sub = subjectsById.get(sess.subject_id);
          return {
            date: sess.date,
            code: sub ? sub.code : '',
            subject: sub ? sub.name : '',
            type: sess.type || 'Lecture',
            status: r.status,
            markedAt: r.marked_at
          };
        })
        .sort((a, b) => String(b.date).localeCompare(String(a.date)))
        .slice(0, 10);

      const studentObj = {
        uuid: stuRow.id,
        profileId: stuRow.profile_id,
        id: stuRow.student_id,
        name: stuRow.profiles?.name || stuRow.student_id,
        initials: stuRow.profiles?.initials || 'ST',
        email: stuRow.profiles?.email || '',
        phone: stuRow.phone || stuRow.profiles?.phone || '—',
        course: stuRow.course || stuRow.courses?.name || 'B.Tech Computer Engineering',
        department: stuRow.departments?.name || 'Computer Engineering',
        semester: stuRow.semester || 'Semester V',
        academicYear: stuRow.academic_year || '2026–27',
        division: stuRow.division || 'Division A',
        batch: stuRow.batch || 'B1',
        dob: formatLongDate(stuRow.date_of_birth),
        bloodGroup: stuRow.blood_group || '—',
        category: stuRow.category || '—',
        admissionYear: String(stuRow.enrollment_year || new Date().getFullYear()),
        advisor: stuRow.advisor_name || '—',
        guardianName: stuRow.guardian_name || '—',
        guardianPhone: stuRow.guardian_phone || '—',
        address: stuRow.address || '—',
        sgpa: stuRow.sgpa !== null && stuRow.sgpa !== undefined ? Number(stuRow.sgpa) : 0,
        cgpa: stuRow.cgpa !== null && stuRow.cgpa !== undefined ? Number(stuRow.cgpa) : 0,
        semesterHistory: Array.isArray(stuRow.semester_history) ? stuRow.semester_history : [],
        status: stuRow.status || 'Active',
        subjects: subjectsForStu,
        attendanceHistory: historyItems
      };

      studentsList.push(studentObj);
      studentsMap[stuRow.student_id] = studentObj;
    });

    if (global.db && typeof global.db === 'object') {
      global.db.students = studentsMap;
    }

    return studentsList;
  }

  /**
   * Queries Supabase for the Faculty Assigned Student Directory.
   */
  async function getFacultyStudents() {
    return getStudents();
  }

  async function getFacultyCohortData() {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Faculty credentials required.');
    }

    const [
      facListRes,
      studentsList,
      subjectsRes,
      noticesRes,
      activityRes
    ] = await Promise.all([
      sb.from('faculty').select('*,profiles(*),departments(*)'),
      getStudents(),
      sb.from('subjects').select('*').order('code', { ascending: true }),
      sb.from('notices').select('*').order('published_at', { ascending: false }),
      sb.from('faculty_activity').select('*').order('created_at', { ascending: false }).limit(10)
    ]);

    const allSubjects = subjectsRes.data || [];
    const studentsMap = {};
    (studentsList || []).forEach(stu => {
      studentsMap[stu.id] = stu;
    });

    const assignedCourses = allSubjects
      .filter(s => !user.facultyUuid || s.faculty_id === user.facultyUuid)
      .map(s => ({ code: s.code, title: s.name, credits: s.credits, id: s.id }));

    const facultyDirectory = (facListRes.data || []).map(f => ({
      uuid: f.id,
      id: f.faculty_id,
      name: f.profiles?.name || f.faculty_id,
      email: f.profiles?.email || '',
      initials: f.profiles?.initials || 'FA',
      designation: f.designation || 'Associate Professor',
      department: f.departments?.name || 'Computer Engineering',
      role: 'faculty',
      assignedCourses: allSubjects
        .filter(s => s.faculty_id === f.id)
        .map(s => ({ code: s.code, title: s.name, credits: s.credits, id: s.id }))
    }));

    const formattedNotices = (noticesRes.data || []).map(n => ({
      id: n.id,
      title: n.title,
      category: n.category,
      date: formatShortNoticeDate(n.published_at || n.created_at),
      author: n.author_label || 'Office of Academic Affairs, MIT',
      body: n.body,
      published: Boolean(n.published)
    }));

    const formattedActivity = (activityRes.data || []).map(a => ({
      id: a.id,
      action: a.action,
      time: formatActivityTimestamp(a.created_at),
      text: a.description
    }));

    return {
      currentFaculty: {
        uuid: user.facultyUuid,
        id: user.userId,
        name: user.name,
        email: user.email,
        initials: user.initials,
        designation: user.designation,
        department: user.department,
        role: 'faculty',
        assignedCourses: assignedCourses.length ? assignedCourses : allSubjects.slice(0, 3).map(s => ({ code: s.code, title: s.name, credits: s.credits, id: s.id }))
      },
      facultyDirectory,
      students: studentsMap,
      subjects: allSubjects,
      notices: formattedNotices,
      facultyActivity: formattedActivity
    };
  }

  /**
   * Records a new attendance session (`attendance_sessions`) and per-student
   * attendance records (`attendance_records`) in PostgreSQL.
   */
  async function saveAttendance(courseCode, sessionDate, marksByStudentCode = {}) {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only faculty can record attendance.');
    }

    const { data: subject, error: subErr } = await sb
      .from('subjects')
      .select('*')
      .eq('code', String(courseCode).toUpperCase())
      .maybeSingle();

    if (subErr || !subject) {
      throw new Error('Selected subject was not found in the database.');
    }

    const { data: allStudents, error: stuErr } = await sb
      .from('students')
      .select('*')
      .order('student_id', { ascending: true });

    if (stuErr || !allStudents?.length) {
      throw new Error('Unable to load student roster for attendance submission.');
    }

    // 1. Create attendance_sessions record
    const { data: createdSession, error: sessErr } = await sb
      .from('attendance_sessions')
      .insert({
        subject_id: subject.id,
        faculty_id: user.facultyUuid,
        date: sessionDate || new Date().toISOString().slice(0, 10),
        start_time: '09:00',
        end_time: '10:00',
        type: 'Lecture',
        division: 'A',
        batch: 'ALL'
      })
      .select('*')
      .single();

    if (sessErr || !createdSession) {
      throw new Error(sanitizeUserFacingError(sessErr, 'Unable to create attendance session.'));
    }

    // 2. Create attendance_records for each student
    const recordsPayload = allStudents.map(stu => {
      const rawMark = marksByStudentCode[stu.student_id] || 'Present';
      const validStatus = ['Present', 'Absent', 'Late', 'Excused'].includes(rawMark) ? rawMark : 'Present';
      return {
        attendance_session_id: createdSession.id,
        student_id: stu.id,
        status: validStatus,
        marked_by: user.facultyUuid,
        marked_at: new Date().toISOString()
      };
    });

    const { error: recErr } = await sb.from('attendance_records').insert(recordsPayload);
    if (recErr) {
      throw new Error(sanitizeUserFacingError(recErr, 'Unable to save student attendance records.'));
    }

    // 3. Log faculty activity
    if (user.facultyUuid) {
      await logFacultyActivity(
        user.facultyUuid,
        'Recorded attendance',
        `Committed session attendance for ${subject.code} (${allStudents.length} students) on ${sessionDate}`
      );
    }

    return {
      session: createdSession,
      count: recordsPayload.length
    };
  }

  /**
   * Adjusts a student's attendance in PostgreSQL by toggling the most recent
   * Absent record to Present (+1) or the most recent Present record to Absent (-1).
   */
  async function adjustSubjectAttendanceInDB(studentCode, courseCode, delta) {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only faculty can adjust attendance.');
    }

    const [{ data: stu }, { data: sub }] = await Promise.all([
      sb.from('students').select('*').eq('student_id', String(studentCode).toUpperCase()).maybeSingle(),
      sb.from('subjects').select('*').eq('code', String(courseCode).toUpperCase()).maybeSingle()
    ]);

    if (!stu || !sub) {
      throw new Error('Student or subject record not found.');
    }

    const { data: records } = await sb
      .from('attendance_records')
      .select('*,attendance_sessions(*)')
      .eq('student_id', stu.id);

    const subjectRecords = (records || [])
      .filter(r => r.attendance_sessions && r.attendance_sessions.subject_id === sub.id)
      .sort((a, b) => String(b.attendance_sessions.date).localeCompare(String(a.attendance_sessions.date)));

    if (delta > 0) {
      const targetAbsent = subjectRecords.find(r => r.status === 'Absent');
      if (targetAbsent) {
        const { error } = await sb
          .from('attendance_records')
          .update({ status: 'Present', marked_by: user.facultyUuid, marked_at: new Date().toISOString() })
          .eq('id', targetAbsent.id);
        if (error) throw new Error(sanitizeUserFacingError(error));
      }
    } else if (delta < 0) {
      const targetPresent = subjectRecords.find(r => r.status === 'Present' || r.status === 'Late' || r.status === 'Excused');
      if (targetPresent) {
        const { error } = await sb
          .from('attendance_records')
          .update({ status: 'Absent', marked_by: user.facultyUuid, marked_at: new Date().toISOString() })
          .eq('id', targetPresent.id);
        if (error) throw new Error(sanitizeUserFacingError(error));
      }
    }

    return true;
  }

  /**
   * Updates a student's marks & grade in PostgreSQL (`grades` table) and recalculates SGPA.
   */
  async function saveGrades(studentCode, courseCode, { int1, int2, endSem }) {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only faculty can update student grades.');
    }

    const nInt1 = Number(int1);
    const nInt2 = Number(int2);
    const nEnd = Number(endSem);

    if (isNaN(nInt1) || nInt1 < 0 || nInt1 > 20) {
      throw new Error('Internal Assessment I marks must be between 0 and 20.');
    }
    if (isNaN(nInt2) || nInt2 < 0 || nInt2 > 20) {
      throw new Error('Internal Assessment II marks must be between 0 and 20.');
    }
    if (isNaN(nEnd) || nEnd < 0 || nEnd > 60) {
      throw new Error('End-Semester marks must be between 0 and 60.');
    }

    const total = nInt1 + nInt2 + nEnd;
    const grade = computeLetterGrade(total);

    const [{ data: stu }, { data: sub }] = await Promise.all([
      sb.from('students').select('*,profiles(*)').eq('student_id', String(studentCode).toUpperCase()).maybeSingle(),
      sb.from('subjects').select('*').eq('code', String(courseCode).toUpperCase()).maybeSingle()
    ]);

    if (!stu || !sub) {
      throw new Error('Student or subject not found.');
    }

    const { data: savedGrade, error: gradeErr } = await sb
      .from('grades')
      .upsert({
        student_id: stu.id,
        subject_id: sub.id,
        academic_year: stu.academic_year || '2026–27',
        semester: stu.semester || 'Semester V',
        internal_1: nInt1,
        internal_2: nInt2,
        end_sem: nEnd,
        total,
        grade,
        updated_by: user.facultyUuid,
        updated_at: new Date().toISOString()
      }, { onConflict: 'student_id,subject_id,academic_year,semester' })
      .select('*')
      .single();

    if (gradeErr) {
      throw new Error(sanitizeUserFacingError(gradeErr, 'Unable to save grade record.'));
    }

    // Recalculate student SGPA from all their PostgreSQL grade records
    const { data: allStuGrades } = await sb
      .from('grades')
      .select('*')
      .eq('student_id', stu.id);

    let newSgpa = Number(stu.sgpa || 0);
    if (allStuGrades && allStuGrades.length > 0) {
      const avgTotal = allStuGrades.reduce((acc, g) => acc + Number(g.total || 0), 0) / allStuGrades.length;
      newSgpa = Number(Math.min(10, Math.max(4, (avgTotal / 10) + 0.3)).toFixed(2));
      const newCgpa = stu.cgpa && Number(stu.cgpa) > 0 ? Number(stu.cgpa) : newSgpa;
      await sb
        .from('students')
        .update({ sgpa: newSgpa, cgpa: newCgpa, updated_at: new Date().toISOString() })
        .eq('id', stu.id);
    }

    const stuName = stu.profiles?.name || stu.student_id;
    if (user.facultyUuid) {
      await logFacultyActivity(
        user.facultyUuid,
        'Updated grades',
        `Updated ${sub.code} marks & grade (${grade}) for ${stuName} (${stu.student_id})`
      );
    }

    return {
      gradeRecord: savedGrade,
      total,
      grade,
      sgpa: newSgpa,
      studentName: stuName
    };
  }

  const saveGrade = saveGrades;

  // ==========================================================================
  // 5. WEEKLY TIMETABLE DATA LAYER
  // ==========================================================================

  /**
   * Formats a PostgreSQL `timetables` row + `timetable_entries` rows into the
   * structure expected by the frontend timetable components.
   */
  function mapTimetableRowFromDB(ttRow, catalogMaps = {}) {
    if (!ttRow) return null;
    const { facultyByUuid = new Map(), coursesByUuid = new Map(), deptsByUuid = new Map() } = catalogMaps;

    const statusCap = String(ttRow.status || 'draft').toLowerCase() === 'published' ? 'Published' : 'Draft';
    const rawEntries = Array.isArray(ttRow.timetable_entries) ? ttRow.timetable_entries : [];

    const mappedEntries = rawEntries.map(e => {
      const facObj = e.faculty || facultyByUuid.get(e.faculty_id);
      const facCode = facObj?.faculty_id || 'FAC2026101';
      const facName = facObj?.profiles?.name || facObj?.name || 'Dr. Rajeshwari Deshmukh';
      const courseName = coursesByUuid.get(e.course_id)?.name || 'B.Tech Computer Engineering';
      const deptName = deptsByUuid.get(e.department_id)?.name || 'Computer Engineering';

      return {
        id: e.id,
        timetableId: e.timetable_id,
        date: e.date,
        day: e.day,
        startTime: String(e.start_time || '').slice(0, 5),
        endTime: String(e.end_time || '').slice(0, 5),
        subject: e.subject_name,
        subjectCode: e.subject_code,
        subjectId: e.subject_id,
        facultyUuid: e.faculty_id,
        facultyId: facCode,
        facultyName: facName,
        course: courseName,
        courseId: e.course_id,
        department: deptName,
        departmentId: e.department_id,
        semester: e.semester || 'Semester V',
        division: e.division || 'A',
        batch: e.batch || 'ALL',
        group: e.group_code || 'ALL',
        room: e.room,
        type: e.type || 'Lecture',
        status: e.entry_status || 'Scheduled'
      };
    });

    mappedEntries.sort((a, b) => {
      const d = String(a.date || '').localeCompare(String(b.date || ''));
      if (d !== 0) return d;
      return String(a.startTime || '').localeCompare(String(b.startTime || ''));
    });

    return {
      id: ttRow.id,
      weekStart: ttRow.week_start,
      weekEnd: ttRow.week_end,
      status: statusCap,
      publishedAt: ttRow.published_at,
      entries: mappedEntries
    };
  }

  async function loadCatalogLookupMaps() {
    const { data: sessionData } = await sb.auth.getSession();
    const sessionRole = sessionData?.session?.user?.user_metadata?.role || null;
    const shouldQueryFaculty = sessionRole !== 'student';

    const [facRes, coursesRes, deptsRes, subjectsRes] = await Promise.all([
      shouldQueryFaculty ? sb.from('faculty').select('*,profiles(*)') : Promise.resolve({ data: [] }),
      sb.from('courses').select('*'),
      sb.from('departments').select('*'),
      sb.from('subjects').select('*')
    ]);
    const facultyByUuid = new Map();
    const facultyByCode = new Map();
    (facRes.data || []).forEach(f => {
      facultyByUuid.set(f.id, f);
      facultyByCode.set(String(f.faculty_id).toUpperCase(), f);
    });
    const coursesByUuid = new Map((coursesRes.data || []).map(c => [c.id, c]));
    const deptsByUuid = new Map((deptsRes.data || []).map(d => [d.id, d]));
    const subjectsByCode = new Map((subjectsRes.data || []).map(s => [String(s.code).toUpperCase(), s]));
    return {
      facultyByUuid,
      facultyByCode,
      coursesByUuid,
      deptsByUuid,
      subjectsByCode,
      coursesList: coursesRes.data || [],
      deptsList: deptsRes.data || []
    };
  }

  /**
   * Retrieves the timetable and its entries for a given week_start from PostgreSQL.
   * RLS ensures students only receive published timetables and entries matching their cohort.
   */
  async function getCurrentTimetable(weekStartISO) {
    const [ttRes, catalogMaps] = await Promise.all([
      sb.from('timetables')
        .select('*,timetable_entries(*,faculty(*))')
        .eq('week_start', weekStartISO)
        .maybeSingle(),
      loadCatalogLookupMaps()
    ]);

    if (ttRes.error) {
      throw new Error(sanitizeUserFacingError(ttRes.error, 'Unable to load weekly timetable.'));
    }

    if (!ttRes.data) return null;
    return mapTimetableRowFromDB(ttRes.data, catalogMaps);
  }

  async function getAllTimetablesFromDB() {
    const [ttRes, catalogMaps] = await Promise.all([
      sb.from('timetables')
        .select('*,timetable_entries(*,faculty(*))')
        .order('week_start', { ascending: true }),
      loadCatalogLookupMaps()
    ]);
    if (ttRes.error) {
      throw new Error(sanitizeUserFacingError(ttRes.error, 'Unable to load timetables.'));
    }
    return (ttRes.data || []).map(row => mapTimetableRowFromDB(row, catalogMaps));
  }

  /**
   * Creates or updates a weekly timetable record in PostgreSQL (`timetables` table).
   */
  async function createTimetableInDB(weekStartISO, weekEndISO, status = 'draft') {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only faculty can create or modify timetables.');
    }

    const dbStatus = String(status || 'draft').toLowerCase() === 'published' ? 'published' : 'draft';
    const { data, error } = await sb
      .from('timetables')
      .upsert({
        week_start: weekStartISO,
        week_end: weekEndISO,
        status: dbStatus,
        created_by: user.facultyUuid,
        published_at: dbStatus === 'published' ? new Date().toISOString() : null,
        updated_at: new Date().toISOString()
      }, { onConflict: 'week_start' })
      .select('*,timetable_entries(*,faculty(*))')
      .single();

    if (error) {
      throw new Error(sanitizeUserFacingError(error, 'Unable to initialize weekly timetable.'));
    }

    if (user.facultyUuid) {
      await logFacultyActivity(
        user.facultyUuid,
        'Updated timetable',
        `Initialized weekly timetable (${weekStartISO} to ${weekEndISO})`
      );
    }

    const catalogMaps = await loadCatalogLookupMaps();
    return mapTimetableRowFromDB(data, catalogMaps);
  }

  const createTimetable = createTimetableInDB;

  /**
   * Inserts or updates a class session entry in `timetable_entries` in PostgreSQL.
   */
  async function saveTimetableEntryInDB(weekStartISO, weekEndISO, entryInput, existingEntryId = null) {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only faculty can modify timetable entries.');
    }

    const catalogMaps = await loadCatalogLookupMaps();

    // Ensure parent timetable exists
    let { data: ttRow } = await sb
      .from('timetables')
      .select('*')
      .eq('week_start', weekStartISO)
      .maybeSingle();

    if (!ttRow) {
      const { data: createdTt, error: ttErr } = await sb
        .from('timetables')
        .insert({
          week_start: weekStartISO,
          week_end: weekEndISO,
          status: 'draft',
          created_by: user.facultyUuid
        })
        .select('*')
        .single();
      if (ttErr) throw new Error(sanitizeUserFacingError(ttErr, 'Unable to create parent timetable week.'));
      ttRow = createdTt;
    }

    // Resolve foreign keys
    const subCode = String(entryInput.subjectCode || '').trim().toUpperCase();
    const matchedSubject = catalogMaps.subjectsByCode.get(subCode);

    const facCodeRaw = String(entryInput.facultyId || '').trim().toUpperCase();
    const normFacCode = facCodeRaw === 'FAC204' ? 'FAC2026101' : (facCodeRaw === 'FAC209' ? 'FAC2026102' : facCodeRaw);
    const matchedFaculty = catalogMaps.facultyByCode.get(normFacCode) || catalogMaps.facultyByUuid.get(entryInput.facultyId) || Array.from(catalogMaps.facultyByUuid.values())[0];

    const matchedDept = catalogMaps.deptsList.find(d =>
      d.name.toLowerCase() === String(entryInput.department || '').trim().toLowerCase()
    ) || catalogMaps.deptsList[0];

    const matchedCourse = catalogMaps.coursesList.find(c =>
      c.name.toLowerCase() === String(entryInput.course || '').trim().toLowerCase() ||
      c.department_id === matchedDept?.id
    ) || catalogMaps.coursesList[0];

    const payload = {
      timetable_id: ttRow.id,
      date: entryInput.date,
      day: entryInput.day,
      start_time: entryInput.startTime,
      end_time: entryInput.endTime,
      subject_id: matchedSubject ? matchedSubject.id : null,
      subject_code: subCode,
      subject_name: entryInput.subject,
      faculty_id: matchedFaculty ? matchedFaculty.id : user.facultyUuid,
      course_id: matchedCourse ? matchedCourse.id : null,
      department_id: matchedDept ? matchedDept.id : null,
      semester: entryInput.semester || 'Semester V',
      division: entryInput.division || 'A',
      batch: entryInput.batch || 'ALL',
      group_code: entryInput.group || 'ALL',
      room: entryInput.room,
      type: entryInput.type || 'Lecture',
      entry_status: entryInput.status || 'Scheduled',
      updated_at: new Date().toISOString()
    };

    let savedEntry;
    if (existingEntryId) {
      const { data, error } = await sb
        .from('timetable_entries')
        .update(payload)
        .eq('id', existingEntryId)
        .select('*')
        .single();
      if (error) throw new Error(sanitizeUserFacingError(error, 'Unable to update timetable entry.'));
      savedEntry = data;
    } else {
      const { data, error } = await sb
        .from('timetable_entries')
        .insert(payload)
        .select('*')
        .single();
      if (error) throw new Error(sanitizeUserFacingError(error, 'Unable to save timetable entry.'));
      savedEntry = data;
    }

    if (user.facultyUuid) {
      await logFacultyActivity(
        user.facultyUuid,
        'Updated timetable',
        `${existingEntryId ? 'Updated' : 'Scheduled'} ${subCode} (${entryInput.day}, ${entryInput.startTime}–${entryInput.endTime}) · Div ${entryInput.division}`
      );
    }

    const updatedTimetable = await getCurrentTimetable(weekStartISO);
    return { entry: savedEntry, timetable: updatedTimetable };
  }

  async function deleteTimetableEntryFromDB(entryId) {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only faculty can delete timetable entries.');
    }

    const { error } = await sb.from('timetable_entries').delete().eq('id', entryId);
    if (error) {
      throw new Error(sanitizeUserFacingError(error, 'Unable to delete timetable entry.'));
    }

    if (user.facultyUuid) {
      await logFacultyActivity(user.facultyUuid, 'Updated timetable', 'Removed class entry from weekly timetable');
    }
    return true;
  }

  async function setTimetablePublishStateInDB(weekStartISO, weekEndISO, publish = true) {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only faculty can publish or unpublish timetables.');
    }

    const dbStatus = publish ? 'published' : 'draft';
    const { data, error } = await sb
      .from('timetables')
      .upsert({
        week_start: weekStartISO,
        week_end: weekEndISO,
        status: dbStatus,
        created_by: user.facultyUuid,
        published_at: publish ? new Date().toISOString() : null,
        updated_at: new Date().toISOString()
      }, { onConflict: 'week_start' })
      .select('*,timetable_entries(*,faculty(*))')
      .single();

    if (error) {
      throw new Error(sanitizeUserFacingError(error, 'Unable to update timetable publication status.'));
    }

    if (user.facultyUuid) {
      await logFacultyActivity(
        user.facultyUuid,
        publish ? 'Published timetable' : 'Unpublished timetable',
        `${publish ? 'Published' : 'Reverted to draft'} weekly timetable for week of ${weekStartISO}`
      );
    }

    const catalogMaps = await loadCatalogLookupMaps();
    return mapTimetableRowFromDB(data, catalogMaps);
  }

  async function clearTimetableWeekInDB(timetableId, weekStartISO) {
    const user = await getCurrentUser();
    if (!user || user.role !== 'faculty') {
      throw new Error('Permission denied: Only faculty can clear weekly timetables.');
    }

    const { error } = await sb.from('timetable_entries').delete().eq('timetable_id', timetableId);
    if (error) {
      throw new Error(sanitizeUserFacingError(error, 'Unable to clear timetable entries for this week.'));
    }

    if (user.facultyUuid) {
      await logFacultyActivity(
        user.facultyUuid,
        'Cleared timetable week',
        `Cleared all scheduled sessions for week of ${weekStartISO}`
      );
    }

    return true;
  }

  // ==========================================================================
  // 6. SUPABASE REALTIME SUBSCRIPTIONS (Cross-Browser Live Sync)
  // ==========================================================================
  let activeRealtimeChannel = null;

  function subscribeToPortalRealtime(handlers = {}) {
    if (!sb || typeof sb.channel !== 'function') return null;
    if (activeRealtimeChannel) {
      sb.removeChannel(activeRealtimeChannel);
      activeRealtimeChannel = null;
    }

    const ch = sb.channel('mit-portal-realtime');

    ch.on('postgres_changes', { event: '*', schema: 'public', table: 'students' }, payload => {
      if (typeof handlers.onStudentsChange === 'function') handlers.onStudentsChange(payload);
    });
    ch.on('postgres_changes', { event: '*', schema: 'public', table: 'profiles' }, payload => {
      if (typeof handlers.onStudentsChange === 'function') handlers.onStudentsChange(payload);
    });
    ch.on('postgres_changes', { event: '*', schema: 'public', table: 'attendance_records' }, payload => {
      if (typeof handlers.onAttendanceChange === 'function') handlers.onAttendanceChange(payload);
    });
    ch.on('postgres_changes', { event: '*', schema: 'public', table: 'grades' }, payload => {
      if (typeof handlers.onGradesChange === 'function') handlers.onGradesChange(payload);
    });
    ch.on('postgres_changes', { event: '*', schema: 'public', table: 'notices' }, payload => {
      if (typeof handlers.onNoticesChange === 'function') handlers.onNoticesChange(payload);
    });
    ch.on('postgres_changes', { event: '*', schema: 'public', table: 'timetables' }, payload => {
      if (typeof handlers.onTimetablesChange === 'function') handlers.onTimetablesChange(payload);
    });
    ch.on('postgres_changes', { event: '*', schema: 'public', table: 'timetable_entries' }, payload => {
      if (typeof handlers.onTimetablesChange === 'function') handlers.onTimetablesChange(payload);
    });

    ch.subscribe();
    activeRealtimeChannel = ch;
    return ch;
  }

  // Export clean API surface
  global.PortalAPI = {
    getCurrentUser,
    signInPortalUser,
    signOutPortalUser,
    registerStudentAccount,
    getStudentProfile,
    getStudents,
    getFacultyStudents,
    getStudentAttendance,
    getStudentGrades,
    getPublishedNotices,
    createNotice,
    updateNotice,
    deleteNoticeRecord,
    getFacultyCohortData,
    saveAttendance,
    adjustSubjectAttendanceInDB,
    saveGrades,
    saveGrade,
    logFacultyActivity,
    getCurrentTimetable,
    getAllTimetablesFromDB,
    createTimetableInDB,
    createTimetable,
    saveTimetableEntryInDB,
    deleteTimetableEntryFromDB,
    setTimetablePublishStateInDB,
    clearTimetableWeekInDB,
    subscribeToPortalRealtime,
    sanitizeUserFacingError
  };
})(typeof window !== 'undefined' ? window : globalThis);
