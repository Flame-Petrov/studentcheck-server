-- One-off migration: old StudentCheck tables (restored into schema "legacy")
-- -> v2 tables in "public" (created by db/schema.sql).
--
--   createdb work
--   pg_restore -d work <old backup>.dump          -- old tables land in "public"
--   psql -d work -c 'ALTER SCHEMA public RENAME TO legacy; CREATE SCHEMA public;'
--   psql -d work -f db/schema.sql
--   psql -d work -f db/migrate_from_legacy.sql
--
-- Rules
--   * Student and class ids are kept, so saved links and student tokens still
--     point at the same records. Teachers get new user ids after the students.
--   * Old passwords that are not argon2 yet are stored as
--     "legacy-v1:<lookup hash>:<encrypted password>"; the server checks them the
--     old way and replaces them with argon2 at the next login.
--   * Scans (attendance_timestamps) become dated lessons: one lesson per class
--     per Sofia calendar day, or more when one student scanned several times
--     that day. Their text timestamps ("26.02.2026 г., 13:50:06") are parsed as
--     Sofia local time.
--   * Attendance counts without scans become lessons without a date, and the
--     class's old completed-lessons count is topped up with undated lessons, so
--     every student keeps the same "attended of total" numbers.
--   * Every enrolled student without a record in a lesson is marked absent.

BEGIN;

SET LOCAL TIME ZONE 'Europe/Sofia';

-- ---------- Helpers ----------

CREATE FUNCTION pg_temp.parse_legacy_time(value text) RETURNS timestamptz
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN value IS NULL OR btrim(value) = '' THEN NULL
        WHEN value ~ '^\d{2}\.\d{2}\.\d{4}'
            THEN to_timestamp(regexp_replace(value, '\s*г\.,?', '', 'g'), 'DD.MM.YYYY HH24:MI:SS')
        ELSE value::timestamptz
    END
$$;

-- Matches a free-text label against a code and both language names.
CREATE FUNCTION pg_temp.label_matches(label text, code text, name_bg text, name_en text) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT lower(btrim(label)) IN (lower(code), lower(name_bg), lower(name_en))
$$;

-- ---------- Users ----------

INSERT INTO users (id, role, full_name, email_encrypted, email_hash, password_hash, created_at)
SELECT
    s.id,
    'student',
    btrim(s.full_name),
    COALESCE(s.email_encrypted, s.email),
    s.email_hash,
    CASE
        WHEN s.password_hash LIKE '$argon2%' THEN s.password_hash
        ELSE 'legacy-v1:' || COALESCE(s.password_hash, '') || ':' || COALESCE(s.password, '')
    END,
    COALESCE(s.created AT TIME ZONE 'UTC', now())
FROM legacy.students s;

CREATE TEMP TABLE teacher_ids ON COMMIT DROP AS
SELECT t.id AS old_id, (SELECT max(id) FROM legacy.students) + row_number() OVER (ORDER BY t.id) AS new_id
FROM legacy.teachers t;

INSERT INTO users (id, role, full_name, email_encrypted, email_hash, password_hash, created_at)
SELECT
    m.new_id,
    'teacher',
    btrim(t.full_name),
    COALESCE(t.email_encrypted, t.email),
    t.email_hash,
    CASE
        WHEN t.password_hash LIKE '$argon2%' THEN t.password_hash
        ELSE 'legacy-v1:' || COALESCE(t.password_hash, '') || ':' || COALESCE(t.password, '')
    END,
    COALESCE(t.created, now())
FROM legacy.teachers t
JOIN teacher_ids m ON m.old_id = t.id;

-- ---------- Students ----------

INSERT INTO students (user_id, faculty_number_encrypted, faculty_number_hash, program_id, study_year, group_number)
SELECT
    s.id,
    s.faculty_number_encrypted,
    s.faculty_number_hash,
    (
        SELECT p.id
        FROM programs p
        JOIN faculties f ON f.id = p.faculty_id
        JOIN degrees d   ON d.code = p.degree_code
        WHERE pg_temp.label_matches(s.faculty, f.code, f.name_bg, f.name_en)
          AND pg_temp.label_matches(s.level, d.code, d.name_bg, d.name_en)
          AND pg_temp.label_matches(s.specialization, p.code, p.name_bg, p.name_en)
    ),
    s.course,
    s."group"::smallint
FROM legacy.students s;

-- ---------- Courses and enrollments ----------

-- created_at is set after the lessons exist (earliest lesson, else now).
INSERT INTO courses (id, teacher_id, name)
SELECT c.id, m.new_id, btrim(c.name)
FROM legacy.classes c
JOIN teacher_ids m ON m.old_id = c.teacher_id;

INSERT INTO course_enrollments (course_id, student_id)
SELECT DISTINCT cs.class_id, cs.student_id
FROM legacy.class_students cs
JOIN courses c   ON c.id = cs.class_id
JOIN students st ON st.user_id = cs.student_id;

-- ---------- Dated lessons from scans ----------

CREATE TEMP TABLE scans ON COMMIT DROP AS
SELECT
    t.class_id,
    t.student_id,
    pg_temp.parse_legacy_time(t.joined_at) AS joined_at,
    pg_temp.parse_legacy_time(t.left_at)   AS left_at
FROM legacy.attendance_timestamps t
JOIN courses c   ON c.id = t.class_id
JOIN students st ON st.user_id = t.student_id
WHERE t.joined_at IS NOT NULL OR t.left_at IS NOT NULL;

CREATE TEMP TABLE ranked_scans ON COMMIT DROP AS
SELECT
    s.*,
    'legacy-' || s.class_id || '-' || to_char(COALESCE(s.joined_at, s.left_at), 'YYYY-MM-DD') || '-' ||
        row_number() OVER (
            PARTITION BY s.class_id, s.student_id, (COALESCE(s.joined_at, s.left_at))::date
            ORDER BY COALESCE(s.joined_at, s.left_at)
        ) AS lesson_key
FROM scans s;

INSERT INTO lessons (course_id, started_at, ended_at, client_session_id)
SELECT
    class_id,
    min(COALESCE(joined_at, left_at)),
    max(COALESCE(left_at, joined_at)),
    lesson_key
FROM ranked_scans
GROUP BY class_id, lesson_key;

INSERT INTO attendance_records (lesson_id, student_id, status_code, joined_at, left_at)
SELECT l.id, r.student_id, 'present', r.joined_at, r.left_at
FROM ranked_scans r
JOIN lessons l ON l.course_id = r.class_id AND l.client_session_id = r.lesson_key;

-- ---------- Undated lessons from counts without scans ----------

-- Presences counted in "attendances" that no scan explains.
CREATE TEMP TABLE unexplained ON COMMIT DROP AS
SELECT
    a.class_id,
    a.student_id,
    a.count - COALESCE((SELECT count(*) FROM scans s WHERE s.class_id = a.class_id AND s.student_id = a.student_id), 0) AS extra
FROM legacy.attendances a
JOIN courses c   ON c.id = a.class_id
JOIN students st ON st.user_id = a.student_id;

-- Per class: enough undated lessons for the largest unexplained count, then
-- more until the class reaches its old completed-lessons count.
CREATE TEMP TABLE undated_needed ON COMMIT DROP AS
SELECT
    c.id AS class_id,
    GREATEST(
        COALESCE((SELECT max(u.extra) FROM unexplained u WHERE u.class_id = c.id), 0),
        COALESCE(lc.completed_classes_count, 0) - (SELECT count(*) FROM lessons l WHERE l.course_id = c.id),
        0
    ) AS lesson_count
FROM courses c
JOIN legacy.classes lc ON lc.id = c.id;

INSERT INTO lessons (course_id, started_at, ended_at, client_session_id)
SELECT n.class_id, NULL, NULL, 'legacy-' || n.class_id || '-undated-' || g.i
FROM undated_needed n
CROSS JOIN LATERAL generate_series(1, n.lesson_count) AS g (i);

INSERT INTO attendance_records (lesson_id, student_id, status_code)
SELECT l.id, u.student_id, 'present'
FROM unexplained u
CROSS JOIN LATERAL generate_series(1, u.extra) AS g (i)
JOIN lessons l ON l.course_id = u.class_id AND l.client_session_id = 'legacy-' || u.class_id || '-undated-' || g.i
WHERE u.extra > 0;

-- ---------- Absences ----------

INSERT INTO attendance_records (lesson_id, student_id, status_code)
SELECT l.id, e.student_id, 'absent'
FROM lessons l
JOIN course_enrollments e ON e.course_id = l.course_id
WHERE NOT EXISTS (
    SELECT 1 FROM attendance_records ar WHERE ar.lesson_id = l.id AND ar.student_id = e.student_id
);

-- ---------- Finishing touches ----------

UPDATE lessons SET client_session_id = NULL WHERE client_session_id LIKE 'legacy-%';

UPDATE courses c
SET created_at = COALESCE((SELECT min(l.started_at) FROM lessons l WHERE l.course_id = c.id), c.created_at);

UPDATE course_enrollments e
SET enrolled_at = c.created_at
FROM courses c
WHERE c.id = e.course_id;

SELECT setval(pg_get_serial_sequence('users', 'id'),     (SELECT max(id) FROM users));
SELECT setval(pg_get_serial_sequence('courses', 'id'),   GREATEST((SELECT max(id) FROM courses), 1));
SELECT setval(pg_get_serial_sequence('lessons', 'id'),   GREATEST((SELECT max(id) FROM lessons), 1));

COMMIT;
