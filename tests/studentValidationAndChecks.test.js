const assert = require("assert").strict;
const crypto = require("crypto");
const {
    parseAndValidateGroup,
} = require("../security/inputValidation");
const {
    buildCheckEmailHandler,
    buildCheckFacultyNumberHandler,
} = require("../security/studentEndpointHandlers");

const normalize = (value) =>
    typeof value === "string" ? value.trim().toLowerCase() : String(value || "").trim().toLowerCase();

const hashForLookup = (value) =>
    crypto.createHash("sha256").update(normalize(value), "utf8").digest("hex");

const run = async (name, fn) => {
    try {
        await fn();
        console.log(`PASS: ${name}`);
    } catch (err) {
        console.error(`FAIL: ${name}`);
        throw err;
    }
};

const createRes = () => {
    const out = {
        statusCode: 200,
        body: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        send(payload) {
            this.body = payload;
            return this;
        },
    };
    return out;
};

const runTests = async () => {
    await run("registration group accepts 30, 37, 50", async () => {
        assert.equal(parseAndValidateGroup(30).isValid, true);
        assert.equal(parseAndValidateGroup(37).isValid, true);
        assert.equal(parseAndValidateGroup(50).isValid, true);
    });

    await run("registration group rejects 29 and 51 (regression from old 37-42 gate)", async () => {
        assert.equal(parseAndValidateGroup(29).isValid, false);
        assert.equal(parseAndValidateGroup(51).isValid, false);
    });

    await run("check-email returns exists true/false", async () => {
        const pool = {
            async query(_sql, values) {
                return { rows: values[0] === hashForLookup("user@example.com") ? [{ "?column?": 1 }] : [] };
            },
        };
        const handler = buildCheckEmailHandler({ pool, normalize, hashForLookup, minimumDurationMs: 0 });

        const resTrue = createRes();
        await handler({ body: { email: " USER@example.com " } }, resTrue);
        assert.equal(resTrue.statusCode, 200);
        assert.deepEqual(resTrue.body, { exists: true });

        const resFalse = createRes();
        await handler({ body: { email: "none@example.com" } }, resFalse);
        assert.equal(resFalse.statusCode, 200);
        assert.deepEqual(resFalse.body, { exists: false });
    });

    await run("check-faculty-number returns exists true/false", async () => {
        const pool = {
            async query(_sql, values) {
                return { rows: values[0] === hashForLookup("381222005") ? [{ "?column?": 1 }] : [] };
            },
        };
        const handler = buildCheckFacultyNumberHandler({ pool, normalize, hashForLookup, minimumDurationMs: 0 });

        const resTrue = createRes();
        await handler({ body: { facultyNumber: "381222005" } }, resTrue);
        assert.equal(resTrue.statusCode, 200);
        assert.deepEqual(resTrue.body, { exists: true });

        const resFalse = createRes();
        await handler({ body: { facultyNumber: "381222006" } }, resFalse);
        assert.equal(resFalse.statusCode, 200);
        assert.deepEqual(resFalse.body, { exists: false });
    });

    await run("invalid payloads return 400", async () => {
        const pool = { async query() { return { rows: [] }; } };
        const emailHandler = buildCheckEmailHandler({ pool, normalize, hashForLookup, minimumDurationMs: 0 });
        const facultyHandler = buildCheckFacultyNumberHandler({ pool, normalize, hashForLookup, minimumDurationMs: 0 });

        const resEmail = createRes();
        await emailHandler({ body: { email: "not-an-email" } }, resEmail);
        assert.equal(resEmail.statusCode, 400);

        const resFaculty = createRes();
        await facultyHandler({ body: { facultyNumber: "abc" } }, resFaculty);
        assert.equal(resFaculty.statusCode, 400);
    });

    await run("SQL injection-style inputs are rejected safely", async () => {
        let queryCalled = false;
        const pool = {
            async query() {
                queryCalled = true;
                return { rows: [] };
            },
        };
        const emailHandler = buildCheckEmailHandler({ pool, normalize, hashForLookup, minimumDurationMs: 0 });
        const facultyHandler = buildCheckFacultyNumberHandler({ pool, normalize, hashForLookup, minimumDurationMs: 0 });

        const resEmail = createRes();
        await emailHandler({ body: { email: "' OR 1=1 --" } }, resEmail);
        assert.equal(resEmail.statusCode, 400);

        const resFaculty = createRes();
        await facultyHandler({ body: { facultyNumber: "381222005 OR 1=1" } }, resFaculty);
        assert.equal(resFaculty.statusCode, 400);
        assert.equal(queryCalled, false);
    });

    console.log("All student validation/check tests passed.");
};

runTests().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
