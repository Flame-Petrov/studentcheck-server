const { decrypt } = require("./cryptoService");

// Inflate a student row, preferring encrypted fields when present
const inflateStudent = (row) => {
    let email = row.email;
    let facultyNumber = row.faculty_number;

    try {
        if (row.email_encrypted) {
            email = decrypt(row.email_encrypted);
        }
    } catch (e) {
        // Fallback to legacy plaintext if decryption fails
    }

    try {
        if (row.faculty_number_encrypted) {
            facultyNumber = decrypt(row.faculty_number_encrypted);
        }
    } catch (e) {
        // Fallback to legacy plaintext if decryption fails
    }

    return {
        id: row.id,
        full_name: row.full_name,
        email,
        faculty_number: facultyNumber,
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

