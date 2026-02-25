-- Idempotent sequence repair: ensure students.id sequence is >= MAX(id).
SELECT setval(
    pg_get_serial_sequence('students', 'id'),
    COALESCE((SELECT MAX(id) FROM students), 1),
    true
);
