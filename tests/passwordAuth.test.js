const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
    ARGON2_ALGORITHM,
    buildArgon2PasswordFields,
    verifyPasswordWithMigration,
} = require("../security/passwordAuth");

process.env.AUTH_PEPPER = process.env.AUTH_PEPPER || "test-pepper-value";

const legacyHashVerifier = (value) => {
    const hmac = crypto.createHmac("sha256", "legacy-lookup-key");
    hmac.update(String(value), "utf8");
    return hmac.digest("hex");
};

const run = async (name, fn) => {
    try {
        await fn();
        console.log(`PASS: ${name}`);
    } catch (error) {
        console.error(`FAIL: ${name}`);
        throw error;
    }
};

const main = async () => {
    await run("valid plaintext password succeeds for argon2id hash", async () => {
        const plainPassword = "CorrectHorseBatteryStaple!";
        const fields = await buildArgon2PasswordFields(plainPassword);

        const result = await verifyPasswordWithMigration({
            inputPassword: plainPassword,
            rowPassword: fields.password,
            rowPasswordHash: fields.password_hash,
            rowHashAlgorithm: fields.hash_algorithm,
            legacyHashVerifier,
            legacyDecryptor: () => null,
        });

        assert.equal(result.isValid, true);
        assert.equal(result.needsMigration, false);
        assert.equal(result.matchedWith, "argon2id");
    });

    await run("using stored hash string as password fails", async () => {
        const plainPassword = "Pa$$w0rd123";
        const fields = await buildArgon2PasswordFields(plainPassword);

        const result = await verifyPasswordWithMigration({
            inputPassword: fields.password_hash,
            rowPassword: fields.password,
            rowPasswordHash: fields.password_hash,
            rowHashAlgorithm: fields.hash_algorithm,
            legacyHashVerifier,
            legacyDecryptor: () => null,
        });

        assert.equal(result.isValid, false);
        assert.equal(result.needsMigration, false);
        assert.equal(result.matchedWith, null);
    });

    await run("legacy account verifies once then migrates to argon2id", async () => {
        const legacyPassword = "LegacyPass!23";
        const legacyHash = legacyHashVerifier(legacyPassword);

        const legacyCheck = await verifyPasswordWithMigration({
            inputPassword: legacyPassword,
            rowPassword: null,
            rowPasswordHash: legacyHash,
            rowHashAlgorithm: null,
            legacyHashVerifier,
            legacyDecryptor: () => null,
        });

        assert.equal(legacyCheck.isValid, true);
        assert.equal(legacyCheck.needsMigration, true);
        assert.equal(legacyCheck.matchedWith, "legacy");

        const upgraded = await buildArgon2PasswordFields(legacyPassword);
        assert.equal(upgraded.hash_algorithm, ARGON2_ALGORITHM);
        assert.notEqual(upgraded.password_hash, legacyHash);

        const upgradedCheck = await verifyPasswordWithMigration({
            inputPassword: legacyPassword,
            rowPassword: upgraded.password,
            rowPasswordHash: upgraded.password_hash,
            rowHashAlgorithm: upgraded.hash_algorithm,
            legacyHashVerifier,
            legacyDecryptor: () => null,
        });

        assert.equal(upgradedCheck.isValid, true);
        assert.equal(upgradedCheck.needsMigration, false);
        assert.equal(upgradedCheck.matchedWith, "argon2id");
    });

    await run("registration password fields store hash metadata and no plaintext", async () => {
        const plainPassword = "RegPassword!55";
        const fields = await buildArgon2PasswordFields(plainPassword);

        assert.equal(fields.password, null);
        assert.equal(fields.hash_algorithm, ARGON2_ALGORITHM);
        assert.ok(fields.password_updated_at instanceof Date);
        assert.ok(typeof fields.password_hash === "string" && fields.password_hash.length > 0);
        assert.notEqual(fields.password_hash, plainPassword);
    });

    console.log("All password auth tests passed.");
};

main().catch((error) => {
    console.error(error && error.stack ? error.stack : error);
    process.exitCode = 1;
});
