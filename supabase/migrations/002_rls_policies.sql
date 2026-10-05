-- ============================================================================
-- MIT ACADEMIC PORTAL — PHASE 1 & 22: ROW LEVEL SECURITY (RLS) POLICIES
-- Migration: 002_rls_policies.sql
-- Enforces strict database-level authorization based on Supabase auth.uid()
-- ============================================================================

-- ============================================================================
-- 1. SECURITY DEFINER AUTH CONTEXT HELPER FUNCTIONS
--    Never trust role, student_id, or faculty_id sent from the browser.
--    Always resolve identity from the verified Supabase JWT (auth.uid()).
-- ============================================================================

CREATE OR REPLACE FUNCTION public.current_profile_id()
RETURNS UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id FROM public.profiles WHERE auth_user_id = auth.uid() LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.current_user_role()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT role FROM public.profiles WHERE auth_user_id = auth.uid() LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.current_student_uuid()
RETURNS UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT s.id
  FROM public.students s
  JOIN public.profiles p ON p.id = s.profile_id
  WHERE p.auth_user_id = auth.uid()
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.current_faculty_uuid()
RETURNS UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT f.id
  FROM public.faculty f
  JOIN public.profiles p ON p.id = f.profile_id
  WHERE p.auth_user_id = auth.uid()
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public. normalize_division_code(p_div TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_raw TEXT := UPPER(TRIM(COALESCE(p_div, '')));
  v_match TEXT[];
BEGIN
  IF v_raw = '' THEN
    RETURN 'A';
  END IF;
  IF v_raw = 'ALL' THEN
    RETURN 'ALL';
  END IF;
  v_match := regexp_match(v_raw, '(?:DIVISION|DIV)\s+([A-Z0-9]+)');
  IF v_match IS NOT NULL AND array_length(v_match, 1) >= 1 THEN
    RETURN v_match[1];
  END IF;
  RETURN split_part(v_raw, ' ', 1);
END;
$$;

CREATE OR REPLACE FUNCTION public.normalize_semester_code(p_sem TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_raw TEXT := UPPER(TRIM(COALESCE(p_sem, '')));
BEGIN
  v_raw := regexp_replace(v_raw, '^SEMESTER\s+', '');
  v_raw := regexp_replace(v_raw, '^SEM\s+', '');
  v_raw := TRIM(v_raw);
  CASE v_raw
    WHEN 'I' THEN RETURN '1';
    WHEN 'II' THEN RETURN '2';
    WHEN 'III' THEN RETURN '3';
    WHEN 'IV' THEN RETURN '4';
    WHEN 'V' THEN RETURN '5';
    WHEN 'VI' THEN RETURN '6';
    WHEN 'VII' THEN RETURN '7';
    WHEN 'VIII' THEN RETURN '8';
    ELSE RETURN v_raw;
  END CASE;
END;
$$;

-- ============================================================================
-- 2. ENABLE ROW LEVEL SECURITY ON ALL TABLES
-- ============================================================================
ALTER TABLE public.departments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.courses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.faculty ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.student_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attendance_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attendance_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.grades ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.faculty_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.timetables ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.timetable_entries ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 3. DEPARTMENTS & COURSES & SUBJECTS POLICIES (Catalog Reference Data)
-- ============================================================================
DROP POLICY IF EXISTS "departments_select_all" ON public.departments;
CREATE POLICY "departments_select_all"
  ON public.departments FOR SELECT
  TO anon, authenticated
  USING (true);

DROP POLICY IF EXISTS "departments_modify_faculty" ON public.departments;
CREATE POLICY "departments_modify_faculty"
  ON public.departments FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

DROP POLICY IF EXISTS "courses_select_all" ON public.courses;
CREATE POLICY "courses_select_all"
  ON public.courses FOR SELECT
  TO anon, authenticated
  USING (true);

DROP POLICY IF EXISTS "courses_modify_faculty" ON public.courses;
CREATE POLICY "courses_modify_faculty"
  ON public.courses FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

DROP POLICY IF EXISTS "subjects_select_all" ON public.subjects;
CREATE POLICY "subjects_select_all"
  ON public.subjects FOR SELECT
  TO anon, authenticated
  USING (true);

DROP POLICY IF EXISTS "subjects_modify_faculty" ON public.subjects;
CREATE POLICY "subjects_modify_faculty"
  ON public.subjects FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

-- ============================================================================
-- 4. PROFILES POLICIES
--    - Users can read their own profile
--    - Authenticated users can read faculty profiles (for instructor/advisor display)
--    - Faculty can read all student profiles
--    - Public registration can ONLY create a 'student' profile for auth.uid()
-- ============================================================================
DROP POLICY IF EXISTS "profiles_select_policy" ON public.profiles;
CREATE POLICY "profiles_select_policy"
  ON public.profiles FOR SELECT
  TO authenticated
  USING (
    auth_user_id = auth.uid()
    OR role = 'faculty'
    OR public.current_user_role() = 'faculty'
  );

DROP POLICY IF EXISTS "profiles_insert_student_only" ON public.profiles;
CREATE POLICY "profiles_insert_student_only"
  ON public.profiles FOR INSERT
  TO authenticated
  WITH CHECK (
    auth_user_id = auth.uid()
    AND role = 'student'
  );

DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own"
  ON public.profiles FOR UPDATE
  TO authenticated
  USING (auth_user_id = auth.uid())
  WITH CHECK (
    auth_user_id = auth.uid()
    AND role = public.current_user_role()
  );

-- ============================================================================
-- 5. STUDENTS POLICIES
--    - Student A can ONLY read their own student record (never Student B's)
--    - Faculty can read & update student academic records
--    - Student can insert their own student record during registration
-- ============================================================================
DROP POLICY IF EXISTS "students_select_own_or_faculty" ON public.students;
CREATE POLICY "students_select_own_or_faculty"
  ON public.students FOR SELECT
  TO authenticated
  USING (
    profile_id = public.current_profile_id()
    OR public.current_user_role() = 'faculty'
  );

DROP POLICY IF EXISTS "students_insert_own" ON public.students;
CREATE POLICY "students_insert_own"
  ON public.students FOR INSERT
  TO authenticated
  WITH CHECK (
    profile_id = public.current_profile_id()
    AND public.current_user_role() = 'student'
  );

DROP POLICY IF EXISTS "students_update_faculty" ON public.students;
CREATE POLICY "students_update_faculty"
  ON public.students FOR UPDATE
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

-- ============================================================================
-- 6. FACULTY POLICIES
--    - Authenticated users can read faculty records
--    - NO public/student INSERT policy (Faculty accounts cannot be self-registered)
-- ============================================================================
DROP POLICY IF EXISTS "faculty_select_authenticated" ON public.faculty;
CREATE POLICY "faculty_select_authenticated"
  ON public.faculty FOR SELECT
  TO authenticated
  USING (true);

DROP POLICY IF EXISTS "faculty_update_own" ON public.faculty;
CREATE POLICY "faculty_update_own"
  ON public.faculty FOR UPDATE
  TO authenticated
  USING (profile_id = public.current_profile_id() AND public.current_user_role() = 'faculty')
  WITH CHECK (profile_id = public.current_profile_id() AND public.current_user_role() = 'faculty');

-- ============================================================================
-- 7. STUDENT_SUBJECTS POLICIES
--    - Students can read ONLY their own subject enrollments
--    - Faculty can read and manage all subject enrollments
-- ============================================================================
DROP POLICY IF EXISTS "student_subjects_select_policy" ON public.student_subjects;
CREATE POLICY "student_subjects_select_policy"
  ON public.student_subjects FOR SELECT
  TO authenticated
  USING (
    student_id = public.current_student_uuid()
    OR public.current_user_role() = 'faculty'
  );

DROP POLICY IF EXISTS "student_subjects_insert_policy" ON public.student_subjects;
CREATE POLICY "student_subjects_insert_policy"
  ON public.student_subjects FOR INSERT
  TO authenticated
  WITH CHECK (
    student_id = public.current_student_uuid()
    OR public.current_user_role() = 'faculty'
  );

DROP POLICY IF EXISTS "student_subjects_modify_faculty" ON public.student_subjects;
CREATE POLICY "student_subjects_modify_faculty"
  ON public.student_subjects FOR UPDATE
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

DROP POLICY IF EXISTS "student_subjects_delete_faculty" ON public.student_subjects;
CREATE POLICY "student_subjects_delete_faculty"
  ON public.student_subjects FOR DELETE
  TO authenticated
  USING (public.current_user_role() = 'faculty');

-- ============================================================================
-- 8. ATTENDANCE_SESSIONS & ATTENDANCE_RECORDS POLICIES
--    - Students can ONLY read their own attendance records & associated sessions
--    - Students CANNOT insert, update, or delete attendance
--    - Faculty can read, insert, update, and delete attendance
-- ============================================================================
DROP POLICY IF EXISTS "attendance_sessions_select_policy" ON public.attendance_sessions;
CREATE POLICY "attendance_sessions_select_policy"
  ON public.attendance_sessions FOR SELECT
  TO authenticated
  USING (
    public.current_user_role() = 'faculty'
    OR EXISTS (
      SELECT 1 FROM public.attendance_records ar
      WHERE ar.attendance_session_id = attendance_sessions.id
        AND ar.student_id = public.current_student_uuid()
    )
    OR EXISTS (
      SELECT 1 FROM public.student_subjects ss
      WHERE ss.subject_id = attendance_sessions.subject_id
        AND ss.student_id = public.current_student_uuid()
    )
  );

DROP POLICY IF EXISTS "attendance_sessions_faculty_write" ON public.attendance_sessions;
CREATE POLICY "attendance_sessions_faculty_write"
  ON public.attendance_sessions FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

DROP POLICY IF EXISTS "attendance_records_select_policy" ON public.attendance_records;
CREATE POLICY "attendance_records_select_policy"
  ON public.attendance_records FOR SELECT
  TO authenticated
  USING (
    student_id = public.current_student_uuid()
    OR public.current_user_role() = 'faculty'
  );

DROP POLICY IF EXISTS "attendance_records_faculty_write" ON public.attendance_records;
CREATE POLICY "attendance_records_faculty_write"
  ON public.attendance_records FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

-- ============================================================================
-- 9. GRADES POLICIES
--    - Students can ONLY read their own grades (never other students' grades)
--    - Students CANNOT insert, update, or delete grades
--    - Faculty can read, insert, and update grades
-- ============================================================================
DROP POLICY IF EXISTS "grades_select_policy" ON public.grades;
CREATE POLICY "grades_select_policy"
  ON public.grades FOR SELECT
  TO authenticated
  USING (
    student_id = public.current_student_uuid()
    OR public.current_user_role() = 'faculty'
  );

DROP POLICY IF EXISTS "grades_faculty_write" ON public.grades;
CREATE POLICY "grades_faculty_write"
  ON public.grades FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

-- Automatic initial grade & attendance record initializer on student registration
CREATE OR REPLACE FUNCTION public.initialize_new_student_enrollment()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Create initial baseline grade record if not exists
  INSERT INTO public.grades (
    student_id, subject_id, academic_year, semester,
    internal_1, internal_2, end_sem, total, grade
  )
  VALUES (
    NEW.student_id, NEW.subject_id, NEW.academic_year, NEW.semester,
    0, 0, 0, 0, 'P'
  )
  ON CONFLICT (student_id, subject_id, academic_year, semester) DO NOTHING;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_init_student_enrollment ON public.student_subjects;
CREATE TRIGGER trg_init_student_enrollment
  AFTER INSERT ON public.student_subjects
  FOR EACH ROW
  EXECUTE FUNCTION public.initialize_new_student_enrollment();

-- ============================================================================
-- 10. NOTICES POLICIES
--     - Students can ONLY read published notices (published = TRUE)
--     - Faculty can read, create, update, and delete notices
-- ============================================================================
DROP POLICY IF EXISTS "notices_select_policy" ON public.notices;
CREATE POLICY "notices_select_policy"
  ON public.notices FOR SELECT
  TO authenticated
  USING (
    published = TRUE
    OR public.current_user_role() = 'faculty'
  );

DROP POLICY IF EXISTS "notices_faculty_write" ON public.notices;
CREATE POLICY "notices_faculty_write"
  ON public.notices FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

-- ============================================================================
-- 11. FACULTY_ACTIVITY POLICIES
--     - Only Faculty can read and insert faculty activity logs
-- ============================================================================
DROP POLICY IF EXISTS "faculty_activity_faculty_only" ON public.faculty_activity;
CREATE POLICY "faculty_activity_faculty_only"
  ON public.faculty_activity FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

-- ============================================================================
-- 12. TIMETABLES & TIMETABLE_ENTRIES POLICIES
--     - Students can ONLY read published timetables
--     - Students can ONLY read timetable_entries belonging to a published
--       timetable that match their own course, department, semester, division,
--       and batch (e.g. Division A student cannot see Division B entries)
--     - Faculty can read and manage all timetables and entries
-- ============================================================================
DROP POLICY IF EXISTS "timetables_select_policy" ON public.timetables;
CREATE POLICY "timetables_select_policy"
  ON public.timetables FOR SELECT
  TO authenticated
  USING (
    LOWER(status) = 'published'
    OR public.current_user_role() = 'faculty'
  );

DROP POLICY IF EXISTS "timetables_faculty_write" ON public.timetables;
CREATE POLICY "timetables_faculty_write"
  ON public.timetables FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');

DROP POLICY IF EXISTS "timetable_entries_select_policy" ON public.timetable_entries;
CREATE POLICY "timetable_entries_select_policy"
  ON public.timetable_entries FOR SELECT
  TO authenticated
  USING (
    public.current_user_role() = 'faculty'
    OR (
      EXISTS (
        SELECT 1
        FROM public.timetables t
        WHERE t.id = timetable_entries.timetable_id
          AND LOWER(t.status) = 'published'
      )
      AND EXISTS (
        SELECT 1
        FROM public.students s
        JOIN public.profiles p ON p.id = s.profile_id
        WHERE p.auth_user_id = auth.uid()
          AND (
            timetable_entries.department_id IS NULL
            OR s.department_id = timetable_entries.department_id
          )
          AND public.normalize_semester_code(s.semester) = public.normalize_semester_code(timetable_entries.semester)
          AND (
            public.normalize_division_code(timetable_entries.division) = 'ALL'
            OR public.normalize_division_code(s.division) = public.normalize_division_code(timetable_entries.division)
          )
          AND (
            UPPER(COALESCE(timetable_entries.batch, 'ALL')) = 'ALL'
            OR UPPER(COALESCE(s.batch, 'ALL')) = 'ALL'
            OR UPPER(COALESCE(s.batch, 'ALL')) = UPPER(COALESCE(timetable_entries.batch, 'ALL'))
          )
      )
    )
  );

DROP POLICY IF EXISTS "timetable_entries_faculty_write" ON public.timetable_entries;
CREATE POLICY "timetable_entries_faculty_write"
  ON public.timetable_entries FOR ALL
  TO authenticated
  USING (public.current_user_role() = 'faculty')
  WITH CHECK (public.current_user_role() = 'faculty');
