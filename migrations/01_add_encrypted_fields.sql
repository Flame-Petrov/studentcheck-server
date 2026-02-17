ALTER TABLE students
  ADD COLUMN IF NOT EXISTS email_encrypted TEXT,
  ADD COLUMN IF NOT EXISTS email_hash TEXT,
  ADD COLUMN IF NOT EXISTS faculty_number_encrypted TEXT,
  ADD COLUMN IF NOT EXISTS faculty_number_hash TEXT;

ALTER TABLE teachers
  ADD COLUMN IF NOT EXISTS email_encrypted TEXT,
  ADD COLUMN IF NOT EXISTS email_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_students_email_hash ON students (email_hash);
CREATE INDEX IF NOT EXISTS idx_students_faculty_number_hash ON students (faculty_number_hash);
CREATE INDEX IF NOT EXISTS idx_teachers_email_hash ON teachers (email_hash);

