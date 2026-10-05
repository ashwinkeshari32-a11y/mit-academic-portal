-- ============================================================================
-- MIT ACADEMIC PORTAL — PHASE 1: INITIAL POSTGRESQL SCHEMA
-- Migration: 001_initial_schema.sql
-- Target: Supabase PostgreSQL 15+
-- ============================================================================

-- Enable UUID generation extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. AUTOMATIC UPDATED_AT TRIGGER FUNCTION
-- ============================================================================
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

-- ============================================================================
-- 2. DEPARTMENTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.departments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  code TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- 3. COURSES / PROGRAMMES
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.courses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  code TEXT NOT NULL UNIQUE,
  department_id UUID NOT NULL REFERENCES public.departments(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_courses_department_id ON public.courses(department_id);

-- ============================================================================
-- 4. PROFILES (Linked 1:1 with Supabase auth.users)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('student', 'faculty')),
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  initials TEXT NOT NULL DEFAULT 'MIT',
  phone TEXT,
  department_id UUID REFERENCES public.departments(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_profiles_auth_user_id ON public.profiles(auth_user_id);
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_profiles_email_lower ON public.profiles(LOWER(email));

DROP TRIGGER IF EXISTS trg_profiles_updated_at ON public.profiles;
CREATE TRIGGER trg_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ============================================================================
-- 5. STUDENTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.students (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id UUID NOT NULL UNIQUE REFERENCES public.profiles(id) ON DELETE CASCADE,
  student_id TEXT NOT NULL UNIQUE,
  course TEXT NOT NULL,
  course_id UUID REFERENCES public.courses(id) ON DELETE SET NULL,
  department_id UUID NOT NULL REFERENCES public.departments(id) ON DELETE RESTRICT,
  semester TEXT NOT NULL,
  academic_year TEXT NOT NULL DEFAULT '2026–27',
  division TEXT NOT NULL DEFAULT 'A',
  batch TEXT NOT NULL DEFAULT 'B1',
  roll_no TEXT,
  date_of_birth DATE,
  blood_group TEXT NOT NULL DEFAULT 'O+',
  category TEXT NOT NULL DEFAULT 'Open Merit',
  phone TEXT,
  enrollment_year INTEGER NOT NULL DEFAULT 2024 CHECK (enrollment_year >= 2000 AND enrollment_year <= 2100),
  advisor_name TEXT NOT NULL DEFAULT 'Dr. Rajeshwari Deshmukh',
  guardian_name TEXT,
  guardian_phone TEXT,
  address TEXT,
  sgpa NUMERIC(4,2) NOT NULL DEFAULT 8.50 CHECK (sgpa >= 0.00 AND sgpa <= 10.00),
  cgpa NUMERIC(4,2) NOT NULL DEFAULT 8.50 CHECK (cgpa >= 0.00 AND cgpa <= 10.00),
  semester_history JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive', 'Graduated', 'Suspended')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_students_profile_id ON public.students(profile_id);
CREATE INDEX IF NOT EXISTS idx_students_student_id_upper ON public.students(UPPER(student_id));
CREATE INDEX IF NOT EXISTS idx_students_department_id ON public.students(department_id);
CREATE INDEX IF NOT EXISTS idx_students_cohort ON public.students(department_id, semester, division);

DROP TRIGGER IF EXISTS trg_students_updated_at ON public.students;
CREATE TRIGGER trg_students_updated_at
  BEFORE UPDATE ON public.students
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ============================================================================
-- 6. FACULTY
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.faculty (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id UUID NOT NULL UNIQUE REFERENCES public.profiles(id) ON DELETE CASCADE,
  faculty_id TEXT NOT NULL UNIQUE,
  department_id UUID NOT NULL REFERENCES public.departments(id) ON DELETE RESTRICT,
  designation TEXT NOT NULL DEFAULT 'Assistant Professor',
  status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive', 'On Leave')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_faculty_profile_id ON public.faculty(profile_id);
CREATE INDEX IF NOT EXISTS idx_faculty_faculty_id_upper ON public.faculty(UPPER(faculty_id));
CREATE INDEX IF NOT EXISTS idx_faculty_department_id ON public.faculty(department_id);

DROP TRIGGER IF EXISTS trg_faculty_updated_at ON public.faculty;
CREATE TRIGGER trg_faculty_updated_at
  BEFORE UPDATE ON public.faculty
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ============================================================================
-- 7. SUBJECTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.subjects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  course_id UUID NOT NULL REFERENCES public.courses(id) ON DELETE CASCADE,
  faculty_id UUID REFERENCES public.faculty(id) ON DELETE SET NULL,
  semester TEXT NOT NULL,
  credits INTEGER NOT NULL CHECK (credits > 0 AND credits <= 12),
  subject_type TEXT NOT NULL DEFAULT 'Lecture' CHECK (subject_type IN ('Lecture', 'Lab', 'Tutorial', 'Other')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subjects_course_sem ON public.subjects(course_id, semester);
CREATE INDEX IF NOT EXISTS idx_subjects_faculty_id ON public.subjects(faculty_id);

-- ============================================================================
-- 8. STUDENT SUBJECT ENROLLMENT
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.student_subjects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id UUID NOT NULL REFERENCES public.students(id) ON DELETE CASCADE,
  subject_id UUID NOT NULL REFERENCES public.subjects(id) ON DELETE CASCADE,
  academic_year TEXT NOT NULL DEFAULT '2026–27',
  semester TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_student_subject_term UNIQUE (student_id, subject_id, academic_year, semester)
);

CREATE INDEX IF NOT EXISTS idx_student_subjects_student_id ON public.student_subjects(student_id);
CREATE INDEX IF NOT EXISTS idx_student_subjects_subject_id ON public.student_subjects(subject_id);

-- ============================================================================
-- 9. ATTENDANCE SESSIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.attendance_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_id UUID NOT NULL REFERENCES public.subjects(id) ON DELETE CASCADE,
  faculty_id UUID REFERENCES public.faculty(id) ON DELETE SET NULL,
  date DATE NOT NULL,
  start_time TIME NOT NULL DEFAULT '09:00',
  end_time TIME NOT NULL DEFAULT '10:00',
  type TEXT NOT NULL DEFAULT 'Lecture' CHECK (type IN ('Lecture', 'Lab', 'Lab Practical', 'Tutorial', 'Seminar', 'Other')),
  division TEXT NOT NULL DEFAULT 'A',
  batch TEXT NOT NULL DEFAULT 'ALL',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_attendance_session_times CHECK (start_time < end_time)
);

CREATE INDEX IF NOT EXISTS idx_attendance_sessions_subject_date ON public.attendance_sessions(subject_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_attendance_sessions_faculty ON public.attendance_sessions(faculty_id);

-- ============================================================================
-- 10. ATTENDANCE RECORDS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.attendance_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  attendance_session_id UUID NOT NULL REFERENCES public.attendance_sessions(id) ON DELETE CASCADE,
  student_id UUID NOT NULL REFERENCES public.students(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('Present', 'Absent', 'Late', 'Excused')),
  marked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  marked_by UUID REFERENCES public.faculty(id) ON DELETE SET NULL,
  CONSTRAINT uq_session_student_attendance UNIQUE (attendance_session_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_attendance_records_student_id ON public.attendance_records(student_id);
CREATE INDEX IF NOT EXISTS idx_attendance_records_session_id ON public.attendance_records(attendance_session_id);

-- ============================================================================
-- 11. GRADES
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.grades (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id UUID NOT NULL REFERENCES public.students(id) ON DELETE CASCADE,
  subject_id UUID NOT NULL REFERENCES public.subjects(id) ON DELETE CASCADE,
  academic_year TEXT NOT NULL DEFAULT '2026–27',
  semester TEXT NOT NULL,
  internal_1 NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (internal_1 >= 0 AND internal_1 <= 20),
  internal_2 NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (internal_2 >= 0 AND internal_2 <= 20),
  end_sem NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (end_sem >= 0 AND end_sem <= 60),
  total NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (total >= 0 AND total <= 100),
  grade TEXT NOT NULL CHECK (grade IN ('O', 'A+', 'A', 'B+', 'B', 'P', 'F')),
  updated_by UUID REFERENCES public.faculty(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_student_subject_grade UNIQUE (student_id, subject_id, academic_year, semester),
  CONSTRAINT chk_grades_total_consistency CHECK (total = internal_1 + internal_2 + end_sem)
);

CREATE INDEX IF NOT EXISTS idx_grades_student_id ON public.grades(student_id);
CREATE INDEX IF NOT EXISTS idx_grades_subject_id ON public.grades(subject_id);

DROP TRIGGER IF EXISTS trg_grades_updated_at ON public.grades;
CREATE TRIGGER trg_grades_updated_at
  BEFORE UPDATE ON public.grades
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ============================================================================
-- 12. NOTICES
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.notices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('Academic Notice', 'Examination Notice', 'College Announcement')),
  body TEXT NOT NULL,
  author_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  author_label TEXT,
  published BOOLEAN NOT NULL DEFAULT TRUE,
  published_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notices_published ON public.notices(published, published_at DESC);

DROP TRIGGER IF EXISTS trg_notices_updated_at ON public.notices;
CREATE TRIGGER trg_notices_updated_at
  BEFORE UPDATE ON public.notices
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ============================================================================
-- 13. FACULTY ACTIVITY
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.faculty_activity (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_id UUID NOT NULL REFERENCES public.faculty(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_faculty_activity_faculty_created ON public.faculty_activity(faculty_id, created_at DESC);

-- ============================================================================
-- 14. WEEKLY TIMETABLES
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.timetables (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  week_start DATE NOT NULL UNIQUE,
  week_end DATE NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (LOWER(status) IN ('draft', 'published')),
  created_by UUID REFERENCES public.faculty(id) ON DELETE SET NULL,
  published_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_timetable_week_dates CHECK (week_start <= week_end)
);

CREATE INDEX IF NOT EXISTS idx_timetables_week_start ON public.timetables(week_start);

DROP TRIGGER IF EXISTS trg_timetables_updated_at ON public.timetables;
CREATE TRIGGER trg_timetables_updated_at
  BEFORE UPDATE ON public.timetables
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ============================================================================
-- 15. TIMETABLE ENTRIES
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.timetable_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timetable_id UUID NOT NULL REFERENCES public.timetables(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  day TEXT NOT NULL CHECK (day IN ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')),
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  subject_id UUID REFERENCES public.subjects(id) ON DELETE SET NULL,
  subject_code TEXT NOT NULL,
  subject_name TEXT NOT NULL,
  faculty_id UUID REFERENCES public.faculty(id) ON DELETE SET NULL,
  course_id UUID REFERENCES public.courses(id) ON DELETE SET NULL,
  department_id UUID REFERENCES public.departments(id) ON DELETE SET NULL,
  semester TEXT NOT NULL,
  division TEXT NOT NULL,
  batch TEXT NOT NULL DEFAULT 'ALL',
  group_code TEXT NOT NULL DEFAULT 'ALL',
  room TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'Lecture' CHECK (type IN ('Lecture', 'Lab', 'Practical', 'Tutorial', 'Seminar', 'Other')),
  entry_status TEXT NOT NULL DEFAULT 'Scheduled' CHECK (entry_status IN ('Scheduled', 'Rescheduled', 'Cancelled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_timetable_entry_times CHECK (start_time < end_time)
);

CREATE INDEX IF NOT EXISTS idx_timetable_entries_timetable_date ON public.timetable_entries(timetable_id, date, start_time);
CREATE INDEX IF NOT EXISTS idx_timetable_entries_faculty_date ON public.timetable_entries(faculty_id, date);
CREATE INDEX IF NOT EXISTS idx_timetable_entries_cohort ON public.timetable_entries(course_id, department_id, semester, division);

DROP TRIGGER IF EXISTS trg_timetable_entries_updated_at ON public.timetable_entries;
CREATE TRIGGER trg_timetable_entries_updated_at
  BEFORE UPDATE ON public.timetable_entries
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ============================================================================
-- 16. HELPER RPC: RESOLVE LOGIN IDENTIFIER (Student ID / Faculty ID -> Email)
--     Allows institutional login with Student ID or Faculty ID while using
--     Supabase Auth (email + password) as the single authentication provider.
-- ============================================================================
CREATE OR REPLACE FUNCTION public.resolve_institutional_login_email(p_identifier TEXT)
RETURNS TABLE (email TEXT, role TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_clean TEXT := TRIM(COALESCE(p_identifier, ''));
BEGIN
  IF v_clean = '' THEN
    RETURN;
  END IF;

  -- 1. Direct email match
  IF POSITION('@' IN v_clean) > 0 THEN
    RETURN QUERY
      SELECT p.email, p.role
      FROM public.profiles p
      WHERE LOWER(p.email) = LOWER(v_clean)
      LIMIT 1;
    RETURN;
  END IF;

  -- 2. Student ID match
  RETURN QUERY
    SELECT p.email, p.role
    FROM public.students s
    JOIN public.profiles p ON p.id = s.profile_id
    WHERE UPPER(s.student_id) = UPPER(v_clean)
    LIMIT 1;

  IF FOUND THEN
    RETURN;
  END IF;

  -- 3. Faculty ID match
  RETURN QUERY
    SELECT p.email, p.role
    FROM public.faculty f
    JOIN public.profiles p ON p.id = f.profile_id
    WHERE UPPER(f.faculty_id) = UPPER(v_clean)
    LIMIT 1;
END;
$$;

GRANT EXECUTE ON FUNCTION public.resolve_institutional_login_email(TEXT) TO anon, authenticated;
