const assert = require("assert").strict;
const {
    signAuthToken,
    verifyAuthToken,
    parseAuthorizationHeader,
} = require("../security/teacherAuth");

const TEST_SECRET = "test-secret-123";

const run = async (name, fn) => {
    try {
        await fn();
        console.log(`PASS: ${name}`);
    } catch (err) {
        console.error(`FAIL: ${name}`);
        throw err;
    }
};

const now = Math.floor(Date.now() / 1000);

const runTests = async () => {
    await run("login token signing + verify works", async () => {
        const token = signAuthToken({
            secret: TEST_SECRET,
            payload: { sub: "10", teacherId: 10, role: "teacher", email: "t@example.com", iat: now, exp: now + 60 },
        });
        const payload = verifyAuthToken({ token, secret: TEST_SECRET });
        assert.equal(payload.sub, "10");
        assert.equal(payload.teacherId, 10);
        assert.equal(payload.role, "teacher");
    });

    await run("missing auth header -> missing bearer token", async () => {
        const parsed = parseAuthorizationHeader(undefined);
        assert.equal(parsed.ok, false);
        assert.equal(parsed.error, "Missing bearer token");
    });

    await run("malformed auth header -> invalid bearer token format", async () => {
        const parsed = parseAuthorizationHeader("Token abc");
        assert.equal(parsed.ok, false);
        assert.equal(parsed.error, "Invalid bearer token format");
    });

    await run("expired token -> invalid/expired on verify path", async () => {
        const token = signAuthToken({
            secret: TEST_SECRET,
            payload: { sub: "10", role: "teacher", iat: now - 120, exp: now - 60 },
        });
        const payload = verifyAuthToken({ token, secret: TEST_SECRET });
        assert.equal(payload, null);
    });
};

runTests().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
