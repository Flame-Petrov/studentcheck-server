const {
    normalizeEmailInput,
    normalizeFacultyNumberInput,
    isValidEmail,
    isValidFacultyNumber,
} = require("./inputValidation");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const buildCheckEmailHandler = ({ pool, normalize, hashForLookup, minimumDurationMs = 120 }) => async (req, res) => {
    const startedAtMs = Date.now();
    const finish = async () => {
        const elapsed = Date.now() - startedAtMs;
        const waitMs = Math.max(0, minimumDurationMs - elapsed);
        if (waitMs > 0) await sleep(waitMs);
    };

    try {
        const emailInput = req.body?.email;
        if (typeof emailInput !== "string") {
            await finish();
            return res.status(400).send({ error: "Invalid payload" });
        }

        const normalizedEmail = normalizeEmailInput(emailInput, normalize);
        if (!isValidEmail(normalizedEmail)) {
            await finish();
            return res.status(400).send({ error: "Invalid email format" });
        }

        const emailHash = hashForLookup(normalizedEmail);
        const result = await pool.query("SELECT 1 FROM students WHERE email_hash = $1 LIMIT 1", [emailHash]);
        await finish();
        return res.status(200).send({ exists: result.rows.length > 0 });
    } catch {
        await finish();
        return res.status(500).send({ error: "Internal server error" });
    }
};

const buildCheckFacultyNumberHandler = ({ pool, normalize, hashForLookup, minimumDurationMs = 120 }) => async (req, res) => {
    const startedAtMs = Date.now();
    const finish = async () => {
        const elapsed = Date.now() - startedAtMs;
        const waitMs = Math.max(0, minimumDurationMs - elapsed);
        if (waitMs > 0) await sleep(waitMs);
    };

    try {
        const facultyInput = req.body?.facultyNumber;
        if (typeof facultyInput !== "string") {
            await finish();
            return res.status(400).send({ error: "Invalid payload" });
        }

        const normalizedFacultyNumber = normalizeFacultyNumberInput(facultyInput, normalize);
        if (!isValidFacultyNumber(normalizedFacultyNumber)) {
            await finish();
            return res.status(400).send({ error: "Invalid faculty number format" });
        }

        const facultyHash = hashForLookup(normalizedFacultyNumber);
        const result = await pool.query("SELECT 1 FROM students WHERE faculty_number_hash = $1 LIMIT 1", [facultyHash]);
        await finish();
        return res.status(200).send({ exists: result.rows.length > 0 });
    } catch {
        await finish();
        return res.status(500).send({ error: "Internal server error" });
    }
};

module.exports = {
    buildCheckEmailHandler,
    buildCheckFacultyNumberHandler,
};
