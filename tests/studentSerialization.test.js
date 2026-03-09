const assert = require("assert").strict;

process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || Buffer.alloc(32, 11).toString("base64");
process.env.LOOKUP_HASH_KEY = process.env.LOOKUP_HASH_KEY || Buffer.alloc(32, 22).toString("base64");

const { encryptRaw } = require("../security/cryptoService");
const { resolveEmailForApi, serializeStudent } = require("../security/decryptors");

const run = async (name, fn) => {
    try {
        await fn();
    } catch (err) {
        console.error(`FAIL: ${name}`);
        throw err;
    }
};

const runTests = async () => {
    await run("resolveEmailForApi normalizes plain email", async () => {
        const resolved = resolveEmailForApi("  Student.One@Example.com ");
        assert.equal(resolved, "student.one@example.com");
    });

    await run("resolveEmailForApi decrypts encrypted email payload", async () => {
        const encrypted = encryptRaw("Encrypted.User@Example.com");
        const resolved = resolveEmailForApi(encrypted);
        assert.equal(resolved, "encrypted.user@example.com");
    });

    await run("resolveEmailForApi returns null for undecodable values", async () => {
        const resolved = resolveEmailForApi("not-an-email-and-not-encrypted");
        assert.equal(resolved, null);
    });

    await run("serializeStudent keeps shape and resolves encrypted email", async () => {
        const encryptedEmail = encryptRaw("Mixed.Data@Example.com");
        const serialized = serializeStudent({
            id: 42,
            full_name: "Mixed Data",
            email: encryptedEmail,
            faculty_number: " 381222005 ",
            group: " 41 ",
            course: "3",
            faculty: "FMI",
            level: "bachelor",
            specialization: "SE",
        });

        assert.equal(serialized.id, 42);
        assert.equal(serialized.student_id, 42);
        assert.equal(serialized.faculty_number, "381222005");
        assert.equal(serialized.facultyNumber, "381222005");
        assert.equal(serialized.full_name, "Mixed Data");
        assert.equal(serialized.group, " 41 ");
        assert.equal(serialized.email, "mixed.data@example.com");
        assert.equal(serialized.email_encrypted, encryptedEmail);
        assert.equal(serialized.course, "3");
    });

    await run("serializeStudent falls back to email_encrypted column", async () => {
        const encryptedEmail = encryptRaw("Fallback.User@Example.com");
        const serialized = serializeStudent({
            student_id: 7,
            full_name: "Fallback User",
            email: null,
            email_encrypted: encryptedEmail,
            faculty_number: "abc123",
            group_name: "A-1",
        });

        assert.equal(serialized.id, 7);
        assert.equal(serialized.student_id, 7);
        assert.equal(serialized.group, "A-1");
        assert.equal(serialized.faculty_number, "ABC123");
        assert.equal(serialized.facultyNumber, "ABC123");
        assert.equal(serialized.email, "fallback.user@example.com");
        assert.equal(serialized.email_encrypted, encryptedEmail);
    });
};

runTests().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
