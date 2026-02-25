ALTER TABLE students DROP CONSTRAINT IF EXISTS students_group_check;

ALTER TABLE students
    ADD CONSTRAINT students_group_check
    CHECK ("group" ~ '^[0-9]+$' AND "group"::integer BETWEEN 30 AND 50);

CREATE UNIQUE INDEX IF NOT EXISTS uq_students_email_hash
    ON students (email_hash)
    WHERE email_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_students_faculty_number_hash
    ON students (faculty_number_hash)
    WHERE faculty_number_hash IS NOT NULL;
