"use strict";

// Checks that every account can be found and logged into the way the server does it.
//
//   node scripts/auditAccounts.js          report only (read-only)
//   node scripts/auditAccounts.js --fix    also store correct email / faculty number hashes
//
// Needs the server's DATABASE_URL, ENCRYPTION_KEY, LOOKUP_HASH_KEY and AUTH_PEPPER
// in the environment. Prints account ids only, never emails or passwords.
//
// Per account:
//   email           decrypts to a valid email, and email_hash matches it
//   faculty number  (students) decrypts, and faculty_number_hash matches it;
//                   student login finds the account by this hash
//   password        "legacy-v1:..." values contain the old encrypted password, so
//                   the script decrypts it and runs the server's check on it.
//                   argon2 hashes cannot be tested without the password itself.

const { Pool } = require("pg");
const { hashForLookup, hashExactForLookup, normalize, decrypt } = require("../security/cryptoService");
const { resolveEmailForApi } = require("../security/decryptors");
const { LEGACY_PASSWORD_PREFIX, verifyStoredPassword } = require("../security/passwordAuth");

const FIX = process.argv.includes("--fix");

const tryDecrypt = (value) => {
    try {
        return decrypt(value);
    } catch {
        return null;
    }
};

// The plaintext a legacy-v1 value can be checked with: its encrypted old password.
const legacyPlainPassword = (storedHash) => {
    const legacyPart = storedHash.slice(LEGACY_PASSWORD_PREFIX.length);
    const separatorIndex = legacyPart.indexOf(":");
    if (separatorIndex === -1) return null;
    return tryDecrypt(legacyPart.slice(separatorIndex + 1));
};

const main = async () => {
    if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        const { rows } = await pool.query(`
            SELECT u.id, u.role, u.email_encrypted, u.email_hash, u.password_hash,
                   st.faculty_number_encrypted, st.faculty_number_hash
            FROM users u
            LEFT JOIN students st ON st.user_id = u.id
            ORDER BY u.id
        `);

        const problems = {
            emailNotDecryptable: [],
            emailHashWrong: [],
            facultyNumberNotDecryptable: [],
            facultyNumberHashWrong: [],
            legacyPasswordFails: [],
        };
        const counts = { argon2: 0, legacyVerified: 0, other: 0 };
        const fixes = [];

        for (const row of rows) {
            const email = resolveEmailForApi(row.email_encrypted);
            if (!email) {
                problems.emailNotDecryptable.push(row.id);
            } else if (row.email_hash !== hashForLookup(email)) {
                problems.emailHashWrong.push(row.id);
                fixes.push({ sql: "UPDATE users SET email_hash = $1 WHERE id = $2", values: [hashForLookup(email), row.id], id: row.id, what: "email_hash" });
            }

            if (row.role === "student") {
                const facultyNumber = tryDecrypt(row.faculty_number_encrypted);
                if (!facultyNumber) {
                    problems.facultyNumberNotDecryptable.push(row.id);
                } else {
                    const expected = hashForLookup(normalize(facultyNumber));
                    if (row.faculty_number_hash !== expected) {
                        problems.facultyNumberHashWrong.push(row.id);
                        fixes.push({ sql: "UPDATE students SET faculty_number_hash = $1 WHERE user_id = $2", values: [expected, row.id], id: row.id, what: "faculty_number_hash" });
                    }
                }
            }

            const stored = String(row.password_hash || "");
            if (stored.startsWith("$argon2")) {
                counts.argon2 += 1;
            } else if (stored.startsWith(LEGACY_PASSWORD_PREFIX)) {
                const plain = legacyPlainPassword(stored);
                const result = plain
                    ? await verifyStoredPassword({ inputPassword: plain, storedHash: stored, legacyHashVerifier: hashExactForLookup, legacyDecryptor: tryDecrypt })
                    : { isValid: false };
                if (result.isValid) counts.legacyVerified += 1;
                else problems.legacyPasswordFails.push(row.id);
            } else {
                counts.other += 1;
                problems.legacyPasswordFails.push(row.id);
            }
        }

        const students = rows.filter((row) => row.role === "student").length;
        console.log(`Accounts: ${rows.length} (${students} students, ${rows.length - students} teachers/admins)`);
        console.log(`Passwords: ${counts.argon2} argon2 (not testable without the password), ${counts.legacyVerified} old-format verified, ${problems.legacyPasswordFails.length} old-format FAILING`);
        const report = (label, ids) => console.log(`${label.padEnd(36)} ${ids.length ? `${ids.length}  ids: ${ids.join(", ")}` : "0"}`);
        report("Email does not decrypt:", problems.emailNotDecryptable);
        report("Email hash wrong:", problems.emailHashWrong);
        report("Faculty number does not decrypt:", problems.facultyNumberNotDecryptable);
        report("Faculty number hash wrong (no login):", problems.facultyNumberHashWrong);
        report("Old-format password fails check:", problems.legacyPasswordFails);

        if (!FIX) {
            if (fixes.length) console.log(`\n${fixes.length} hash(es) can be corrected: run again with --fix.`);
            return;
        }

        let fixed = 0;
        for (const fix of fixes) {
            try {
                await pool.query(fix.sql, fix.values);
                fixed += 1;
            } catch (error) {
                console.log(`Could not fix ${fix.what} of id ${fix.id}: ${error.code === "23505" ? "another account already has this value" : error.message}`);
            }
        }
        console.log(`\nFixed ${fixed} of ${fixes.length} hash(es).`);
    } finally {
        await pool.end();
    }
};

main().catch((error) => {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
});
