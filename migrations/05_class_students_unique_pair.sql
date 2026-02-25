CREATE UNIQUE INDEX IF NOT EXISTS uq_class_students_class_id_student_id
    ON class_students (class_id, student_id);
