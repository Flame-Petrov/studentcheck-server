const UNIQUE_VIOLATION_CODE = "23505";
const STUDENTS_PKEY = "students_pkey";
const KNOWN_EMAIL_CONSTRAINTS = new Set([
    "uq_students_email_hash",
    "students_email_hash_key",
]);
const KNOWN_FACULTY_CONSTRAINTS = new Set([
    "uq_students_faculty_number_hash",
    "students_faculty_number_hash_key",
]);

const mapRegistrationUniqueViolation = (error) => {
    if (!error || error.code !== UNIQUE_VIOLATION_CODE) return null;

    const constraint = String(error.constraint || "").toLowerCase();
    if (constraint === STUDENTS_PKEY) {
        return { type: "id_collision", constraint };
    }
    if (KNOWN_EMAIL_CONSTRAINTS.has(constraint)) {
        return { type: "duplicate_email", constraint };
    }
    if (KNOWN_FACULTY_CONSTRAINTS.has(constraint)) {
        return { type: "duplicate_faculty_number", constraint };
    }

    return { type: "unknown_unique_violation", constraint };
};

const resyncStudentsIdSequence = async (pool) => {
    await pool.query(`
        SELECT setval(
            pg_get_serial_sequence('students', 'id'),
            COALESCE((SELECT MAX(id) FROM students), 1),
            true
        );
    `);
};

const insertStudentWithIdCollisionRecovery = async ({
    pool,
    insertSql,
    insertValues,
    requestId,
    logger = console,
}) => {
    try {
        return await pool.query(insertSql, insertValues);
    } catch (error) {
        const mapped = mapRegistrationUniqueViolation(error);
        if (!mapped || mapped.type !== "id_collision") {
            throw error;
        }

        logger.error("[REGISTRATION][ID_COLLISION]", {
            requestId,
            constraint: mapped.constraint,
            message: "students.id sequence drift detected; resyncing sequence and retrying once",
        });

        await resyncStudentsIdSequence(pool);

        try {
            return await pool.query(insertSql, insertValues);
        } catch (retryError) {
            retryError.registrationRetryFailed = true;
            throw retryError;
        }
    }
};

module.exports = {
    mapRegistrationUniqueViolation,
    resyncStudentsIdSequence,
    insertStudentWithIdCollisionRecovery,
};
