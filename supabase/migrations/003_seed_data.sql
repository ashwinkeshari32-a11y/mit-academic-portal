-- ============================================================================
-- MIT ACADEMIC PORTAL — PHASE 1 & 34: DEVELOPMENT / DEMO SEED DATA
-- Migration: 003_seed_data.sql
-- NOTE: Contains ONLY synthetic development/demo data for portal testing.
--       Does NOT contain any real/private student personal information.
-- ============================================================================

DO $$
DECLARE
  -- Department UUIDs
  v_dept_comp UUID := '11111111-1111-4111-8111-111111111101';
  v_dept_cs   UUID := '11111111-1111-4111-8111-111111111102';
  v_dept_it   UUID := '11111111-1111-4111-8111-111111111103';
  v_dept_aiml UUID := '11111111-1111-4111-8111-111111111104';
  v_dept_elec UUID := '11111111-1111-4111-8111-111111111105';

  -- Course UUIDs
  v_course_btech_comp UUID := '22222222-2222-4222-8222-222222222201';
  v_course_btech_it   UUID := '22222222-2222-4222-8222-222222222202';
  v_course_btech_aiml UUID := '22222222-2222-4222-8222-222222222203';

  -- Auth User UUIDs (Demo accounts)
  v_auth_fac1 UUID := '33333333-3333-4333-8333-333333333101';
  v_auth_fac2 UUID := '33333333-3333-4333-8333-333333333102';
  v_auth_stu1 UUID := '33333333-3333-4333-8333-333333333001';
  v_auth_stu2 UUID := '33333333-3333-4333-8333-333333333002';
  v_auth_stu3 UUID := '33333333-3333-4333-8333-333333333003';
  v_auth_stu4 UUID := '33333333-3333-4333-8333-333333333004';
  v_auth_stu5 UUID := '33333333-3333-4333-8333-333333333005';

  -- Profile UUIDs
  v_prof_fac1 UUID := '44444444-4444-4444-8444-444444444101';
  v_prof_fac2 UUID := '44444444-4444-4444-8444-444444444102';
  v_prof_stu1 UUID := '44444444-4444-4444-8444-444444444001';
  v_prof_stu2 UUID := '44444444-4444-4444-8444-444444444002';
  v_prof_stu3 UUID := '44444444-4444-4444-8444-444444444003';
  v_prof_stu4 UUID := '44444444-4444-4444-8444-444444444004';
  v_prof_stu5 UUID := '44444444-4444-4444-8444-444444444005';

  -- Faculty Record UUIDs
  v_fac1 UUID := '55555555-5555-4555-8555-555555555101';
  v_fac2 UUID := '55555555-5555-4555-8555-555555555102';

  -- Student Record UUIDs
  v_stu1 UUID := '66666666-6666-4666-8666-666666666001';
  v_stu2 UUID := '66666666-6666-4666-8666-666666666002';
  v_stu3 UUID := '66666666-6666-4666-8666-666666666003';
  v_stu4 UUID := '66666666-6666-4666-8666-666666666004';
  v_stu5 UUID := '66666666-6666-4666-8666-666666666005';

  -- Subject UUIDs
  v_sub_cs501 UUID := '77777777-7777-4777-8777-777777777501';
  v_sub_cs502 UUID := '77777777-7777-4777-8777-777777777502';
  v_sub_cs503 UUID := '77777777-7777-4777-8777-777777777503';
  v_sub_cs504 UUID := '77777777-7777-4777-8777-777777777504';
  v_sub_cs505 UUID := '77777777-7777-4777-8777-777777777505';

  -- Timetable UUID
  v_tt_week1 UUID := '88888888-8888-4888-8888-888888888001';

  v_session_id UUID;
  i INTEGER;
BEGIN
  -- --------------------------------------------------------------------------
  -- 1. DEPARTMENTS
  -- --------------------------------------------------------------------------
  INSERT INTO public.departments (id, name, code) VALUES
    (v_dept_comp, 'Computer Engineering', 'COMP'),
    (v_dept_cs,   'Computer Science', 'CSE'),
    (v_dept_it,   'Information Technology', 'IT'),
    (v_dept_aiml, 'Artificial Intelligence & Machine Learning', 'AIML'),
    (v_dept_elec, 'Electrical Engineering', 'ELEC')
  ON CONFLICT (code) DO NOTHING;

  -- --------------------------------------------------------------------------
  -- 2. COURSES
  -- --------------------------------------------------------------------------
  INSERT INTO public.courses (id, name, code, department_id) VALUES
    (v_course_btech_comp, 'B.Tech Computer Engineering', 'BTECH-COMP', v_dept_comp),
    (v_course_btech_it,   'B.Tech Information Technology', 'BTECH-IT', v_dept_it),
    (v_course_btech_aiml, 'B.Tech Artificial Intelligence & Machine Learning', 'BTECH-AIML', v_dept_aiml)
  ON CONFLICT (code) DO NOTHING;

  -- --------------------------------------------------------------------------
  -- 3. DEMO SUPABASE AUTH USERS (Development Seed Only)
  --    Uses pgcrypto crypt() for bcrypt hashing inside auth.users
  -- --------------------------------------------------------------------------
  INSERT INTO auth.users (
    id, instance_id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at
  ) VALUES
    (v_auth_fac1, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
     'rajeshwari.deshmukh@mitmumbai.edu.in', crypt('FAC2026101', gen_salt('bf')),
     NOW(), '{"provider":"email","providers":["email"]}', '{"role":"faculty","faculty_id":"FAC2026101"}', NOW(), NOW()),
    (v_auth_fac2, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
     'vikram.joshi@mitmumbai.edu.in', crypt('FAC2026102', gen_salt('bf')),
     NOW(), '{"provider":"email","providers":["email"]}', '{"role":"faculty","faculty_id":"FAC2026102"}', NOW(), NOW()),
    (v_auth_stu1, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
     'princekumar.sharma@mitmumbai.edu.in', crypt('MIT2026001', gen_salt('bf')),
     NOW(), '{"provider":"email","providers":["email"]}', '{"role":"student","student_id":"MIT2026001"}', NOW(), NOW()),
    (v_auth_stu2, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
     'ananya.kulkarni@mitmumbai.edu.in', crypt('MIT2026002', gen_salt('bf')),
     NOW(), '{"provider":"email","providers":["email"]}', '{"role":"student","student_id":"MIT2026002"}', NOW(), NOW()),
    (v_auth_stu3, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
     'rohan.deshmukh@mitmumbai.edu.in', crypt('MIT2026003', gen_salt('bf')),
     NOW(), '{"provider":"email","providers":["email"]}', '{"role":"student","student_id":"MIT2026003"}', NOW(), NOW()),
    (v_auth_stu4, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
     'meera.joshi@mitmumbai.edu.in', crypt('MIT2026004', gen_salt('bf')),
     NOW(), '{"provider":"email","providers":["email"]}', '{"role":"student","student_id":"MIT2026004"}', NOW(), NOW()),
    (v_auth_stu5, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
     'siddharth.patil@mitmumbai.edu.in', crypt('MIT2026005', gen_salt('bf')),
     NOW(), '{"provider":"email","providers":["email"]}', '{"role":"student","student_id":"MIT2026005"}', NOW(), NOW())
  ON CONFLICT (id) DO NOTHING;

  -- --------------------------------------------------------------------------
  -- 4. PROFILES
  -- --------------------------------------------------------------------------
  INSERT INTO public.profiles (id, auth_user_id, role, name, email, initials, phone, department_id) VALUES
    (v_prof_fac1, v_auth_fac1, 'faculty', 'Dr. Rajeshwari Deshmukh', 'rajeshwari.deshmukh@mitmumbai.edu.in', 'RD', '+91 98200 10101', v_dept_comp),
    (v_prof_fac2, v_auth_fac2, 'faculty', 'Prof. Vikramaditya Joshi', 'vikram.joshi@mitmumbai.edu.in', 'VJ', '+91 98200 10102', v_dept_comp),
    (v_prof_stu1, v_auth_stu1, 'student', 'Princekumar Sharma', 'princekumar.sharma@mitmumbai.edu.in', 'PS', '+91 98204 51289', v_dept_comp),
    (v_prof_stu2, v_auth_stu2, 'student', 'Ananya Kulkarni', 'ananya.kulkarni@mitmumbai.edu.in', 'AK', '+91 98192 33410', v_dept_comp),
    (v_prof_stu3, v_auth_stu3, 'student', 'Rohan Deshmukh', 'rohan.deshmukh@mitmumbai.edu.in', 'RD', '+91 97654 11920', v_dept_comp),
    (v_prof_stu4, v_auth_stu4, 'student', 'Meera Joshi', 'meera.joshi@mitmumbai.edu.in', 'MJ', '+91 98231 66501', v_dept_comp),
    (v_prof_stu5, v_auth_stu5, 'student', 'Siddharth Patil', 'siddharth.patil@mitmumbai.edu.in', 'SP', '+91 99208 44123', v_dept_comp)
  ON CONFLICT (id) DO NOTHING;

  -- --------------------------------------------------------------------------
  -- 5. FACULTY
  -- --------------------------------------------------------------------------
  INSERT INTO public.faculty (id, profile_id, faculty_id, department_id, designation, status) VALUES
    (v_fac1, v_prof_fac1, 'FAC2026101', v_dept_comp, 'Associate Professor', 'Active'),
    (v_fac2, v_prof_fac2, 'FAC2026102', v_dept_comp, 'Assistant Professor', 'Active')
  ON CONFLICT (faculty_id) DO NOTHING;

  -- --------------------------------------------------------------------------
  -- 6. STUDENTS (Synthetic Demo Records)
  -- --------------------------------------------------------------------------
  INSERT INTO public.students (
    id, profile_id, student_id, course, course_id, department_id,
    semester, academic_year, division, batch, roll_no,
    date_of_birth, blood_group, category, phone, enrollment_year,
    advisor_name, guardian_name, guardian_phone, address,
    sgpa, cgpa, semester_history, status
  ) VALUES
    (
      v_stu1, v_prof_stu1, 'MIT2026001', 'B.Tech Computer Engineering', v_course_btech_comp, v_dept_comp,
      'Semester V', '2026–27', 'Division A · Roll No. 14', 'B1', '14',
      '2005-08-14', 'O+', 'Open Merit', '+91 98204 51289', 2024,
      'Dr. Rajeshwari Deshmukh', 'Rajesh Sharma', '+91 98201 11402',
      'Flat 402, Shantiniketan Residency, Kothrud / Mumbai Campus Hostel Block C [Demo]',
      9.56, 9.42,
      '[
        {"sem":"Semester I","ay":"2024–25","sgpa":9.20,"credits":22,"status":"Passed with Distinction"},
        {"sem":"Semester II","ay":"2024–25","sgpa":9.35,"credits":22,"status":"Passed with Distinction"},
        {"sem":"Semester III","ay":"2025–26","sgpa":9.48,"credits":23,"status":"Passed with Distinction"},
        {"sem":"Semester IV","ay":"2025–26","sgpa":9.52,"credits":23,"status":"Passed with Distinction"}
      ]'::jsonb,
      'Active'
    ),
    (
      v_stu2, v_prof_stu2, 'MIT2026002', 'B.Tech Computer Engineering', v_course_btech_comp, v_dept_comp,
      'Semester V', '2026–27', 'Division A · Roll No. 04', 'B1', '04',
      '2005-11-22', 'A+', 'Open Merit', '+91 98192 33410', 2024,
      'Dr. Rajeshwari Deshmukh', 'Milind Kulkarni', '+91 98190 77812',
      '12, Saraswati Baug, Dadar West, Mumbai 400028 [Demo]',
      9.68, 9.60,
      '[
        {"sem":"Semester I","ay":"2024–25","sgpa":9.50,"credits":22,"status":"Passed with Distinction"},
        {"sem":"Semester II","ay":"2024–25","sgpa":9.58,"credits":22,"status":"Passed with Distinction"},
        {"sem":"Semester III","ay":"2025–26","sgpa":9.62,"credits":23,"status":"Passed with Distinction"},
        {"sem":"Semester IV","ay":"2025–26","sgpa":9.68,"credits":23,"status":"Passed with Distinction"}
      ]'::jsonb,
      'Active'
    ),
    (
      v_stu3, v_prof_stu3, 'MIT2026003', 'B.Tech Computer Engineering', v_course_btech_comp, v_dept_comp,
      'Semester V', '2026–27', 'Division A · Roll No. 21', 'B1', '21',
      '2005-03-03', 'B+', 'Open Merit', '+91 97654 11920', 2024,
      'Dr. Rajeshwari Deshmukh', 'Sanjay Deshmukh', '+91 97650 88210',
      'Sector 7, Vashi, Navi Mumbai 400703 [Demo]',
      7.45, 7.62,
      '[
        {"sem":"Semester I","ay":"2024–25","sgpa":7.80,"credits":22,"status":"First Class"},
        {"sem":"Semester II","ay":"2024–25","sgpa":7.65,"credits":22,"status":"First Class"},
        {"sem":"Semester III","ay":"2025–26","sgpa":7.50,"credits":23,"status":"First Class"},
        {"sem":"Semester IV","ay":"2025–26","sgpa":7.45,"credits":23,"status":"First Class"}
      ]'::jsonb,
      'Active'
    ),
    (
      v_stu4, v_prof_stu4, 'MIT2026004', 'B.Tech Computer Engineering', v_course_btech_comp, v_dept_comp,
      'Semester V', '2026–27', 'Division A · Roll No. 29', 'B1', '29',
      '2005-05-19', 'AB+', 'Open Merit', '+91 98231 66501', 2024,
      'Dr. Rajeshwari Deshmukh', 'Prakash Joshi', '+91 98230 11900',
      '45, Prabhat Road, Pune / Mumbai Hostel Block A [Demo]',
      8.85, 8.74,
      '[
        {"sem":"Semester I","ay":"2024–25","sgpa":8.60,"credits":22,"status":"Passed with Distinction"},
        {"sem":"Semester II","ay":"2024–25","sgpa":8.70,"credits":22,"status":"Passed with Distinction"},
        {"sem":"Semester III","ay":"2025–26","sgpa":8.80,"credits":23,"status":"Passed with Distinction"},
        {"sem":"Semester IV","ay":"2025–26","sgpa":8.85,"credits":23,"status":"Passed with Distinction"}
      ]'::jsonb,
      'Active'
    ),
    (
      v_stu5, v_prof_stu5, 'MIT2026005', 'B.Tech Computer Engineering', v_course_btech_comp, v_dept_comp,
      'Semester V', '2026–27', 'Division A · Roll No. 38', 'B1', '38',
      '2005-01-09', 'O+', 'Open Merit', '+91 99208 44123', 2024,
      'Dr. Rajeshwari Deshmukh', 'Ashok Patil', '+91 99200 44120',
      'Hiranandani Gardens, Powai, Mumbai 400076 [Demo]',
      8.32, 8.20,
      '[
        {"sem":"Semester I","ay":"2024–25","sgpa":8.10,"credits":22,"status":"First Class"},
        {"sem":"Semester II","ay":"2024–25","sgpa":8.15,"credits":22,"status":"First Class"},
        {"sem":"Semester III","ay":"2025–26","sgpa":8.25,"credits":23,"status":"Passed with Distinction"},
        {"sem":"Semester IV","ay":"2025–26","sgpa":8.32,"credits":23,"status":"Passed with Distinction"}
      ]'::jsonb,
      'Active'
    )
  ON CONFLICT (student_id) DO NOTHING;

  -- --------------------------------------------------------------------------
  -- 7. SUBJECTS
  -- --------------------------------------------------------------------------
  INSERT INTO public.subjects (id, code, name, course_id, faculty_id, semester, credits, subject_type) VALUES
    (v_sub_cs501, 'CS501', 'Design & Analysis of Algorithms', v_course_btech_comp, v_fac1, 'Semester V', 4, 'Lecture'),
    (v_sub_cs502, 'CS502', 'Operating Systems',               v_course_btech_comp, v_fac1, 'Semester V', 4, 'Lecture'),
    (v_sub_cs503, 'CS503', 'Database Management Systems',     v_course_btech_comp, v_fac1, 'Semester V', 4, 'Lecture'),
    (v_sub_cs504, 'CS504', 'Computer Networks',               v_course_btech_comp, v_fac2, 'Semester V', 4, 'Lecture'),
    (v_sub_cs505, 'CS505', 'Software Engineering & Testing',  v_course_btech_comp, v_fac2, 'Semester V', 3, 'Lecture')
  ON CONFLICT (code) DO NOTHING;

  -- --------------------------------------------------------------------------
  -- 8. STUDENT_SUBJECTS ENROLLMENTS
  -- --------------------------------------------------------------------------
  INSERT INTO public.student_subjects (student_id, subject_id, academic_year, semester)
  SELECT s.id, sub.id, '2026–27', 'Semester V'
  FROM public.students s
  CROSS JOIN public.subjects sub
  WHERE s.student_id IN ('MIT2026001', 'MIT2026002', 'MIT2026003', 'MIT2026004', 'MIT2026005')
  ON CONFLICT (student_id, subject_id, academic_year, semester) DO NOTHING;

  -- --------------------------------------------------------------------------
  -- 9. GRADES
  -- --------------------------------------------------------------------------
  INSERT INTO public.grades (student_id, subject_id, academic_year, semester, internal_1, internal_2, end_sem, total, grade, updated_by) VALUES
    -- MIT2026001
    (v_stu1, v_sub_cs501, '2026–27', 'Semester V', 19, 18, 56, 93, 'O',  v_fac1),
    (v_stu1, v_sub_cs502, '2026–27', 'Semester V', 18, 19, 54, 91, 'O',  v_fac1),
    (v_stu1, v_sub_cs503, '2026–27', 'Semester V', 17, 18, 52, 87, 'A+', v_fac1),
    (v_stu1, v_sub_cs504, '2026–27', 'Semester V', 18, 17, 51, 86, 'A+', v_fac2),
    (v_stu1, v_sub_cs505, '2026–27', 'Semester V', 19, 19, 55, 93, 'O',  v_fac2),
    -- MIT2026002
    (v_stu2, v_sub_cs501, '2026–27', 'Semester V', 20, 19, 57, 96, 'O',  v_fac1),
    (v_stu2, v_sub_cs502, '2026–27', 'Semester V', 19, 19, 56, 94, 'O',  v_fac1),
    (v_stu2, v_sub_cs503, '2026–27', 'Semester V', 19, 20, 55, 94, 'O',  v_fac1),
    (v_stu2, v_sub_cs504, '2026–27', 'Semester V', 18, 18, 52, 88, 'A+', v_fac2),
    (v_stu2, v_sub_cs505, '2026–27', 'Semester V', 19, 18, 54, 91, 'O',  v_fac2),
    -- MIT2026003
    (v_stu3, v_sub_cs501, '2026–27', 'Semester V', 12, 13, 38, 63, 'B+', v_fac1),
    (v_stu3, v_sub_cs502, '2026–27', 'Semester V', 13, 11, 36, 60, 'B+', v_fac1),
    (v_stu3, v_sub_cs503, '2026–27', 'Semester V', 14, 14, 41, 69, 'B+', v_fac1),
    (v_stu3, v_sub_cs504, '2026–27', 'Semester V', 12, 13, 39, 64, 'B+', v_fac2),
    (v_stu3, v_sub_cs505, '2026–27', 'Semester V', 15, 14, 42, 71, 'A',  v_fac2),
    -- MIT2026004
    (v_stu4, v_sub_cs501, '2026–27', 'Semester V', 16, 17, 48, 81, 'A+', v_fac1),
    (v_stu4, v_sub_cs502, '2026–27', 'Semester V', 17, 16, 47, 80, 'A+', v_fac1),
    (v_stu4, v_sub_cs503, '2026–27', 'Semester V', 18, 17, 50, 85, 'A+', v_fac1),
    (v_stu4, v_sub_cs504, '2026–27', 'Semester V', 16, 16, 46, 78, 'A',  v_fac2),
    (v_stu4, v_sub_cs505, '2026–27', 'Semester V', 18, 17, 49, 84, 'A+', v_fac2),
    -- MIT2026005
    (v_stu5, v_sub_cs501, '2026–27', 'Semester V', 15, 16, 44, 75, 'A',  v_fac1),
    (v_stu5, v_sub_cs502, '2026–27', 'Semester V', 15, 15, 43, 73, 'A',  v_fac1),
    (v_stu5, v_sub_cs503, '2026–27', 'Semester V', 16, 15, 45, 76, 'A',  v_fac1),
    (v_stu5, v_sub_cs504, '2026–27', 'Semester V', 14, 15, 42, 71, 'A',  v_fac2),
    (v_stu5, v_sub_cs505, '2026–27', 'Semester V', 16, 16, 46, 78, 'A',  v_fac2)
  ON CONFLICT (student_id, subject_id, academic_year, semester) DO UPDATE SET
    internal_1 = EXCLUDED.internal_1,
    internal_2 = EXCLUDED.internal_2,
    end_sem    = EXCLUDED.end_sem,
    total      = EXCLUDED.total,
    grade      = EXCLUDED.grade,
    updated_by = EXCLUDED.updated_by;

  -- --------------------------------------------------------------------------
  -- 10. ATTENDANCE SESSIONS & RECORDS
  --     Seeds historical sessions per subject so calculated attendance
  --     (present_sessions / total_sessions * 100) is derived directly from
  --     attendance_records!
  -- --------------------------------------------------------------------------
  -- CS501: 42 sessions (Stu1: 39, Stu2: 41, Stu3: 27, Stu4: 36, Stu5: 33)
  FOR i IN 1..42 LOOP
    v_session_id := gen_random_uuid();
    INSERT INTO public.attendance_sessions (id, subject_id, faculty_id, date, start_time, end_time, type, division, batch)
    VALUES (
      v_session_id, v_sub_cs501, v_fac1,
      DATE '2026-10-05' - (42 - i),
      '09:00', '10:00', 'Lecture', 'A', 'ALL'
    );
    INSERT INTO public.attendance_records (attendance_session_id, student_id, status, marked_by) VALUES
      (v_session_id, v_stu1, CASE WHEN i <= 39 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu2, CASE WHEN i <= 41 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu3, CASE WHEN i <= 27 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu4, CASE WHEN i <= 36 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu5, CASE WHEN i <= 33 THEN 'Present' ELSE 'Absent' END, v_fac1);
  END LOOP;

  -- CS502: 40 sessions (Stu1: 38, Stu2: 39, Stu3: 26, Stu4: 34, Stu5: 32)
  FOR i IN 1..40 LOOP
    v_session_id := gen_random_uuid();
    INSERT INTO public.attendance_sessions (id, subject_id, faculty_id, date, start_time, end_time, type, division, batch)
    VALUES (
      v_session_id, v_sub_cs502, v_fac1,
      DATE '2026-10-04' - (40 - i),
      '10:15', '11:15', CASE WHEN i = 40 THEN 'Lab Practical' ELSE 'Lecture' END, 'A', 'ALL'
    );
    INSERT INTO public.attendance_records (attendance_session_id, student_id, status, marked_by) VALUES
      (v_session_id, v_stu1, CASE WHEN i <= 38 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu2, CASE WHEN i <= 39 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu3, CASE WHEN i <= 26 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu4, CASE WHEN i <= 34 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu5, CASE WHEN i <= 32 THEN 'Present' ELSE 'Absent' END, v_fac1);
  END LOOP;

  -- CS503: 40 sessions (Stu1: 36, Stu2: 38, Stu3: 28, Stu4: 35, Stu5: 33)
  FOR i IN 1..40 LOOP
    v_session_id := gen_random_uuid();
    INSERT INTO public.attendance_sessions (id, subject_id, faculty_id, date, start_time, end_time, type, division, batch)
    VALUES (
      v_session_id, v_sub_cs503, v_fac1,
      DATE '2026-10-04' - (40 - i),
      '11:30', '12:30', 'Lecture', 'A', 'ALL'
    );
    INSERT INTO public.attendance_records (attendance_session_id, student_id, status, marked_by) VALUES
      (v_session_id, v_stu1, CASE WHEN i <= 36 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu2, CASE WHEN i <= 38 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu3, CASE WHEN i <= 28 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu4, CASE WHEN i <= 35 THEN 'Present' ELSE 'Absent' END, v_fac1),
      (v_session_id, v_stu5, CASE WHEN i <= 33 THEN 'Present' ELSE 'Absent' END, v_fac1);
  END LOOP;

  -- CS504: 38 sessions (Stu1: 35, Stu2: 36, Stu3: 26, Stu4: 33, Stu5: 31)
  FOR i IN 1..38 LOOP
    v_session_id := gen_random_uuid();
    INSERT INTO public.attendance_sessions (id, subject_id, faculty_id, date, start_time, end_time, type, division, batch)
    VALUES (
      v_session_id, v_sub_cs504, v_fac2,
      DATE '2026-10-03' - (38 - i),
      '14:15', '15:15', 'Lecture', 'A', 'ALL'
    );
    INSERT INTO public.attendance_records (attendance_session_id, student_id, status, marked_by) VALUES
      (v_session_id, v_stu1, CASE WHEN i <= 35 THEN 'Present' ELSE 'Absent' END, v_fac2),
      (v_session_id, v_stu2, CASE WHEN i <= 36 THEN 'Present' ELSE 'Absent' END, v_fac2),
      (v_session_id, v_stu3, CASE WHEN i <= 26 THEN 'Present' ELSE 'Absent' END, v_fac2),
      (v_session_id, v_stu4, CASE WHEN i <= 33 THEN 'Present' ELSE 'Absent' END, v_fac2),
      (v_session_id, v_stu5, CASE WHEN i <= 31 THEN 'Present' ELSE 'Absent' END, v_fac2);
  END LOOP;

  -- CS505: 30 sessions (Stu1: 28, Stu2: 29, Stu3: 21, Stu4: 27, Stu5: 25)
  FOR i IN 1..30 LOOP
    v_session_id := gen_random_uuid();
    INSERT INTO public.attendance_sessions (id, subject_id, faculty_id, date, start_time, end_time, type, division, batch)
    VALUES (
      v_session_id, v_sub_cs505, v_fac2,
      DATE '2026-10-01' - (30 - i),
      '15:30', '16:30', 'Tutorial', 'A', 'ALL'
    );
    INSERT INTO public.attendance_records (attendance_session_id, student_id, status, marked_by) VALUES
      (v_session_id, v_stu1, CASE WHEN i <= 28 THEN 'Present' ELSE 'Absent' END, v_fac2),
      (v_session_id, v_stu2, CASE WHEN i <= 29 THEN 'Present' ELSE 'Absent' END, v_fac2),
      (v_session_id, v_stu3, CASE WHEN i <= 21 THEN 'Present' ELSE 'Absent' END, v_fac2),
      (v_session_id, v_stu4, CASE WHEN i <= 27 THEN 'Present' ELSE 'Absent' END, v_fac2),
      (v_session_id, v_stu5, CASE WHEN i <= 25 THEN 'Present' ELSE 'Absent' END, v_fac2);
  END LOOP;

  -- --------------------------------------------------------------------------
  -- 11. NOTICES
  -- --------------------------------------------------------------------------
  INSERT INTO public.notices (title, category, body, author_id, author_label, published, published_at) VALUES
    (
      'Semester V Mid-Term Examination Schedule (AY 2026–27)',
      'Examination Notice',
      'Mid-Term written examinations for B.Tech Semester V will commence from 19 October 2026. Students must carry their validated MIT Identity Card and Hall Ticket to the examination hall.',
      v_prof_fac1,
      'Controller of Examinations, MIT',
      TRUE,
      TIMESTAMPTZ '2026-10-04 09:00:00+05:30'
    ),
    (
      'Minimum 75% Attendance Compliance Circular',
      'Academic Notice',
      'As per Maharashtra Institute of Technology academic ordinances, students maintaining less than 75% attendance in lectures and laboratory sessions will not be granted term-work certification.',
      v_prof_fac1,
      'Dr. Rajeshwari Deshmukh · Dept. of Computer Engineering',
      TRUE,
      TIMESTAMPTZ '2026-10-02 11:00:00+05:30'
    ),
    (
      'Annual Convocation & Founders Day Academic Symposium',
      'College Announcement',
      'The 39th Annual Institutional Research & Innovation Symposium will be held in the Main Auditorium on 24 October 2026. Final and pre-final year students are invited to submit project abstracts.',
      v_prof_fac1,
      'Office of the Dean (Academic Affairs)',
      TRUE,
      TIMESTAMPTZ '2026-09-29 14:00:00+05:30'
    ),
    (
      'CS503 Database Management Systems Laboratory Evaluation',
      'Academic Notice',
      'Internal continuous assessment for DBMS SQL indexing and query optimization experiments is scheduled in Systems Lab 2 this Friday.',
      v_prof_fac1,
      'Dr. Rajeshwari Deshmukh · Dept. of Computer Engineering',
      TRUE,
      TIMESTAMPTZ '2026-09-27 16:00:00+05:30'
    );

  -- --------------------------------------------------------------------------
  -- 12. FACULTY ACTIVITY
  -- --------------------------------------------------------------------------
  INSERT INTO public.faculty_activity (faculty_id, action, description, created_at) VALUES
    (v_fac1, 'Recorded attendance', 'Recorded Lecture Attendance for CS501 (Design & Analysis of Algorithms) · Div A', TIMESTAMPTZ '2026-10-05 10:35:00+05:30'),
    (v_fac1, 'Updated grades',      'Updated Internal Assessment II marks for CS503 (Database Management Systems)', TIMESTAMPTZ '2026-10-04 16:15:00+05:30'),
    (v_fac1, 'Published notice',    'Published Academic Notice: Minimum 75% Attendance Compliance Circular', TIMESTAMPTZ '2026-10-02 11:00:00+05:30'),
    (v_fac1, 'Reviewed attendance', 'Reviewed low-attendance defaulter list for B.Tech Semester V', TIMESTAMPTZ '2026-09-29 15:00:00+05:30');

  -- --------------------------------------------------------------------------
  -- 13. WEEKLY TIMETABLE (Week of 2026-10-05 to 2026-10-10)
  -- --------------------------------------------------------------------------
  INSERT INTO public.timetables (id, week_start, week_end, status, created_by, published_at)
  VALUES (v_tt_week1, DATE '2026-10-05', DATE '2026-10-10', 'published', v_fac1, NOW())
  ON CONFLICT (week_start) DO NOTHING;

  INSERT INTO public.timetable_entries (
    timetable_id, date, day, start_time, end_time,
    subject_id, subject_code, subject_name, faculty_id,
    course_id, department_id, semester, division, batch, group_code, room, type, entry_status
  ) VALUES
    -- MONDAY - Division A
    (v_tt_week1, DATE '2026-10-05', 'Monday', '09:00', '10:00', v_sub_cs501, 'CS501', 'Design & Analysis of Algorithms', v_fac1, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'LH-302 · Aryabhatta Block', 'Lecture', 'Scheduled'),
    (v_tt_week1, DATE '2026-10-05', 'Monday', '10:15', '11:15', v_sub_cs502, 'CS502', 'Operating Systems Principles', v_fac2, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'LH-304 · Aryabhatta Block', 'Lecture', 'Scheduled'),
    (v_tt_week1, DATE '2026-10-05', 'Monday', '11:30', '13:30', v_sub_cs503, 'CS503', 'Database Management Systems', v_fac1, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'B1', 'G1', 'Systems Lab 2', 'Lab', 'Scheduled'),
    (v_tt_week1, DATE '2026-10-05', 'Monday', '14:15', '15:15', v_sub_cs504, 'CS504', 'Computer Networks & Security', v_fac2, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'LH-305 · Ramanujan Hall', 'Lecture', 'Scheduled'),
    -- MONDAY - Division B
    (v_tt_week1, DATE '2026-10-05', 'Monday', '10:15', '11:15', v_sub_cs501, 'CS501', 'Design & Analysis of Algorithms', v_fac1, v_course_btech_comp, v_dept_comp, 'Semester V', 'B', 'ALL', 'ALL', 'LH-306 · Aryabhatta Block', 'Lecture', 'Scheduled'),
    -- TUESDAY - Division A
    (v_tt_week1, DATE '2026-10-06', 'Tuesday', '09:00', '10:00', v_sub_cs503, 'CS503', 'Database Management Systems', v_fac1, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'LH-302 · Aryabhatta Block', 'Lecture', 'Scheduled'),
    (v_tt_week1, DATE '2026-10-06', 'Tuesday', '10:15', '11:15', v_sub_cs505, 'CS505', 'Software Engineering & Agile', v_fac2, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'Seminar Hall 1 · Tilak Bhavan', 'Lecture', 'Scheduled'),
    (v_tt_week1, DATE '2026-10-06', 'Tuesday', '11:30', '12:30', v_sub_cs501, 'CS501', 'Design & Analysis of Algorithms', v_fac1, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'Tutorial Room 204', 'Tutorial', 'Scheduled'),
    -- WEDNESDAY - Division A
    (v_tt_week1, DATE '2026-10-07', 'Wednesday', '09:00', '10:00', v_sub_cs502, 'CS502', 'Operating Systems Principles', v_fac2, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'LH-304 · Aryabhatta Block', 'Lecture', 'Scheduled'),
    (v_tt_week1, DATE '2026-10-07', 'Wednesday', '10:15', '11:15', v_sub_cs501, 'CS501', 'Design & Analysis of Algorithms', v_fac1, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'LH-302 · Aryabhatta Block', 'Lecture', 'Scheduled'),
    (v_tt_week1, DATE '2026-10-07', 'Wednesday', '14:00', '16:00', v_sub_cs504, 'CS504', 'Computer Networks & Security', v_fac2, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'B1', 'G1', 'Network Protocol Lab 4', 'Practical', 'Scheduled'),
    -- THURSDAY - Division A
    (v_tt_week1, DATE '2026-10-08', 'Thursday', '09:00', '10:00', v_sub_cs503, 'CS503', 'Database Management Systems', v_fac1, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'LH-302 · Aryabhatta Block', 'Lecture', 'Scheduled'),
    (v_tt_week1, DATE '2026-10-08', 'Thursday', '11:30', '12:30', v_sub_cs505, 'CS505', 'Software Engineering & Agile', v_fac2, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'Seminar Hall 1 · Tilak Bhavan', 'Lecture', 'Scheduled'),
    -- FRIDAY - Division A
    (v_tt_week1, DATE '2026-10-09', 'Friday', '09:00', '11:00', v_sub_cs501, 'CS501', 'Design & Analysis of Algorithms', v_fac1, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'B1', 'G1', 'Algorithms & HPC Lab 1', 'Lab', 'Scheduled'),
    (v_tt_week1, DATE '2026-10-09', 'Friday', '11:30', '12:30', v_sub_cs504, 'CS504', 'Computer Networks & Security', v_fac2, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'LH-305 · Ramanujan Hall', 'Lecture', 'Scheduled'),
    -- SATURDAY - Division A
    (v_tt_week1, DATE '2026-10-10', 'Saturday', '10:00', '12:00', v_sub_cs503, 'CS503', 'Database Management Systems', v_fac1, v_course_btech_comp, v_dept_comp, 'Semester V', 'A', 'ALL', 'ALL', 'Systems Lab 2', 'Tutorial', 'Scheduled');
END;
$$;
