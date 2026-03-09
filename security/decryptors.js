const { decrypt } = require("./cryptoService");

const canonicalizeFacultyNumber = (value) => {
    if (value === undefined || value === null) return null;
    const trimmed = String(value).trim();
    if (!trimmed) return null;
    return trimmed.toUpperCase();
};

const parseStudentId = (value) => {
    const parsed = Number.parseInt(String(value), 10);
    if (!Number.isInteger(parsed) || parsed <= 0) return null;
    return parsed;
};

// Inflate a student row, preferring encrypted fields when present
const inflateStudent = (row) => {
    let email = row.email;
    let facultyNumber = row.faculty_number;

    try {
        if (row.email_encrypted) {
            email = decrypt(row.email_encrypted);
        } else if (row.email) {
            email = decrypt(row.email);
        }
    } catch (e) {
        // Fallback to legacy plaintext if decryption fails
    }

    try {
        if (row.faculty_number_encrypted) {
            facultyNumber = decrypt(row.faculty_number_encrypted);
        } else if (row.faculty_number) {
            facultyNumber = decrypt(row.faculty_number);
        }
    } catch (e) {
        // Fallback to legacy plaintext if decryption fails
    }

    const idValue = parseStudentId(row.id ?? row.student_id) ?? row.id ?? row.student_id;
    const normalizedFacultyNumber = canonicalizeFacultyNumber(facultyNumber);

    return {
        id: idValue,
        student_id: idValue,
        full_name: row.full_name,
        email,
        faculty_number: normalizedFacultyNumber,
        facultyNumber: normalizedFacultyNumber,
        group: row.group,
        course: row.course,
        faculty: row.faculty,
        level: row.level,
        specialization: row.specialization,
    };
};

module.exports = {
    inflateStudent,
};

