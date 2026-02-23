ALTER TABLE students
  ADD COLUMN IF NOT EXISTS password_hash TEXT,
  ADD COLUMN IF NOT EXISTS hash_algorithm TEXT,
  ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ;

ALTER TABLE teachers
  ADD COLUMN IF NOT EXISTS password_hash TEXT,
  ADD COLUMN IF NOT EXISTS hash_algorithm TEXT,
  ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ;

ALTER TABLE students ALTER COLUMN password DROP NOT NULL;
ALTER TABLE teachers ALTER COLUMN password DROP NOT NULL;

UPDATE students
SET password = NULL
WHERE hash_algorithm = 'argon2id_v1';

UPDATE teachers
SET password = NULL
WHERE hash_algorithm = 'argon2id_v1';
