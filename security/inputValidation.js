const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const FACULTY_NUMBER_REGEX = /^\d{6,12}$/;

const normalizeEmailInput = (value, normalize) => normalize(value);
const normalizeFacultyNumberInput = (value, normalize) => normalize(value);

const isValidEmail = (email) => EMAIL_REGEX.test(email);
const isValidFacultyNumber = (facultyNumber) => FACULTY_NUMBER_REGEX.test(facultyNumber);

const parseAndValidateGroup = (groupValue) => {
    const parsed = Number.parseInt(String(groupValue), 10);
    if (!Number.isInteger(parsed) || parsed < 30 || parsed > 50) {
        return { isValid: false, parsed: null };
    }
    return { isValid: true, parsed };
};

module.exports = {
    normalizeEmailInput,
    normalizeFacultyNumberInput,
    isValidEmail,
    isValidFacultyNumber,
    parseAndValidateGroup,
};
