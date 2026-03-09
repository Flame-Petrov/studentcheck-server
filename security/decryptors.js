const { decrypt } = require("./cryptoService");

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

const tryDecryptWithServerKey = (value) => {
    if (typeof value !== "string") return null;
    const raw = value.trim();
    if (!raw) return null;
    try {
        return decrypt(raw);
    } catch {
        return null;
    }
};

const normalizeEmailIfValid = (value) => {
    const raw = String(value || "").trim();
    if (!raw) return null;
    if (!EMAIL_REGEX.test(raw)) return null;
    return raw.toLowerCase();
};

const resolveEmailForApi = (raw) => {
    const direct = normalizeEmailIfValid(raw);
    if (direct) return direct;

    const decrypted = tryDecryptWithServerKey(raw);
    const decryptedNormalized = normalizeEmailIfValid(decrypted);
    if (decryptedNormalized) return decryptedNormalized;

    return null;
};

const resolveFacultyNumberForApi = (row = {}) => {
    const candidates = [
        row.faculty_number_encrypted,
        row.faculty_number,
        row.facultyNumber,
    ];

    for (const candidate of candidates) {
        if (candidate === undefined || candidate === null) continue;

        const decrypted = tryDecryptWithServerKey(candidate);
        const resolved = canonicalizeFacultyNumber(decrypted || candidate);
        if (resolved) return resolved;
    }

    return null;
};

const serializeStudent = (row = {}) => {
    const studentIdRaw = row.id ?? row.student_id;
    const studentId = parseStudentId(studentIdRaw) ?? studentIdRaw ?? null;
    const facultyNumber = resolveFacultyNumberForApi(row);
    const email = resolveEmailForApi(row.email) || resolveEmailForApi(row.email_encrypted);
    const rawEmail = row.email_encrypted ?? row.email ?? null;

    return {
        id: studentId,
        student_id: studentId,
        faculty_number: facultyNumber,
        facultyNumber: facultyNumber,
        full_name: row.full_name || "",
        group: row.group_name || row.group || "",
        email,
        email_encrypted: rawEmail,
        course: row.course,
        faculty: row.faculty,
        level: row.level,
        specialization: row.specialization,
    };
};

// Backward-compatible alias used by existing route handlers.
const inflateStudent = (row = {}) => serializeStudent(row);

module.exports = {
    inflateStudent,
    resolveEmailForApi,
    serializeStudent,
    tryDecryptWithServerKey,
};

