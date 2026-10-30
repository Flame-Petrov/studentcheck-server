const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
    LEGACY_PASSWORD_PREFIX,
    hashPassword,
    verifyPasswordWithMigration,
    verifyStoredPassword,
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
    } catch (error) {
        console.error(`FAIL: ${name}`);
        throw error;
    }
};

const main = async () => {
    await run("valid plaintext password succeeds for argon2id hash", async () => {
        const plainPassword = "CorrectHorseBatteryStaple!";
        const passwordHash = await hashPassword(plainPassword);

        const result = await verifyPasswordWithMigration({
            inputPassword: plainPassword,
            rowPassword: null,
            rowPasswordHash: passwordHash,
            rowHashAlgorithm: null,
            legacyHashVerifier,
            legacyDecryptor: () => null,
        });

        assert.equal(result.isValid, true);
        assert.equal(result.needsMigration, false);
        assert.equal(result.matchedWith, "argon2id");
    });

    await run("using stored hash string as password fails", async () => {
        const plainPassword = "Pa$$w0rd123";
        const passwordHash = await hashPassword(plainPassword);

        const result = await verifyPasswordWithMigration({
            inputPassword: passwordHash,
            rowPassword: null,
            rowPasswordHash: passwordHash,
            rowHashAlgorithm: null,
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

        const upgraded = await hashPassword(legacyPassword);
        assert.ok(upgraded.startsWith("$argon2id$"));
        assert.notEqual(upgraded, legacyHash);

        const upgradedCheck = await verifyPasswordWithMigration({
            inputPassword: legacyPassword,
            rowPassword: null,
            rowPasswordHash: upgraded,
            rowHashAlgorithm: null,
            legacyHashVerifier,
            legacyDecryptor: () => null,
        });

        assert.equal(upgradedCheck.isValid, true);
        assert.equal(upgradedCheck.needsMigration, false);
        assert.equal(upgradedCheck.matchedWith, "argon2id");
    });

    await run("hashPassword stores an argon2id hash, never the plaintext", async () => {
        const plainPassword = "RegPassword!55";
        const passwordHash = await hashPassword(plainPassword);

        assert.ok(passwordHash.startsWith("$argon2id$"));
        assert.equal(passwordHash.includes(plainPassword), false);
    });

    await run("stored argon2 hash verifies without migration", async () => {
        const plainPassword = "StoredArgon!1";
        const storedHash = await hashPassword(plainPassword);

        const ok = await verifyStoredPassword({ inputPassword: plainPassword, storedHash, legacyHashVerifier, legacyDecryptor: () => null });
        assert.deepEqual([ok.isValid, ok.needsMigration], [true, false]);

        const wrong = await verifyStoredPassword({ inputPassword: "nope", storedHash, legacyHashVerifier, legacyDecryptor: () => null });
        assert.equal(wrong.isValid, false);
    });

    await run("legacy-v1 value verifies by lookup hash and asks for migration", async () => {
        const plainPassword = "OldLookup!7";
        const storedHash = `${LEGACY_PASSWORD_PREFIX}${legacyHashVerifier(plainPassword)}:c29tZS1jaXBoZXJ0ZXh0`;

        const ok = await verifyStoredPassword({ inputPassword: plainPassword, storedHash, legacyHashVerifier, legacyDecryptor: () => null });
        assert.deepEqual([ok.isValid, ok.needsMigration], [true, true]);

        const wrong = await verifyStoredPassword({ inputPassword: "OldLookup!8", storedHash, legacyHashVerifier, legacyDecryptor: () => null });
        assert.equal(wrong.isValid, false);
    });

    await run("legacy-v1 value verifies by decrypting the old password", async () => {
        const plainPassword = "OldEncrypted:with:colons";
        const storedHash = `${LEGACY_PASSWORD_PREFIX}:ENC(${plainPassword})`;
        const legacyDecryptor = (value) => (value.startsWith("ENC(") ? value.slice(4, -1) : null);

        const ok = await verifyStoredPassword({ inputPassword: plainPassword, storedHash, legacyHashVerifier, legacyDecryptor });
        assert.deepEqual([ok.isValid, ok.needsMigration], [true, true]);

        const wrong = await verifyStoredPassword({ inputPassword: "OldEncrypted", storedHash, legacyHashVerifier, legacyDecryptor });
        assert.equal(wrong.isValid, false);
    });

    await run("empty legacy-v1 value never verifies", async () => {
        const result = await verifyStoredPassword({ inputPassword: "anything", storedHash: `${LEGACY_PASSWORD_PREFIX}:`, legacyHashVerifier, legacyDecryptor: () => null });
        assert.equal(result.isValid, false);
    });

};

main().catch((error) => {
    console.error(error && error.stack ? error.stack : error);
    process.exitCode = 1;
});
