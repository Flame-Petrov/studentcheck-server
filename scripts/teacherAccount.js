"use strict";

// Checks a teacher account, or sets a new password for it.
//
//   node scripts/teacherAccount.js check <email>          does the password I type match?
//   node scripts/teacherAccount.js set-password <email>   store a new password
//
// Needs the server's DATABASE_URL, ENCRYPTION_KEY, LOOKUP_HASH_KEY and
// AUTH_PEPPER in the environment (run it in the Render shell, or copy them
// into your own terminal session). Passwords are typed at the prompt, so they
// stay out of the shell history. Both modes also store the correct
// email_hash if the stored one does not match the email.

const readline = require("readline");
const { Pool } = require("pg");
const { hashForLookup, hashExactForLookup, normalize, decrypt } = require("../security/cryptoService");
const { resolveEmailForApi } = require("../security/decryptors");
const { hashPassword, verifyStoredPassword } = require("../security/passwordAuth");

const [mode, emailArg] = process.argv.slice(2);
const MIN_PASSWORD_LENGTH = 8;

const usage = () => {
    console.error("Usage: node scripts/teacherAccount.js <check|set-password> <email>");
    process.exitCode = 1;
};

// One line reader for the whole run; it buffers lines, so piped input is not
// lost between questions.
let prompt = null;
let promptLines = null;
const ask = async (question) => {
    if (!prompt) {
        prompt = readline.createInterface({ input: process.stdin });
        promptLines = prompt[Symbol.asyncIterator]();
    }
    process.stdout.write(question);
    const { value, done } = await promptLines.next();
    if (done) throw new Error("No input; nothing was changed.");
    return value;
};

const tryDecrypt = (value) => {
    try {
        return decrypt(value);
    } catch {
        return null;
    }
};

const main = async () => {
    if (!["check", "set-password"].includes(mode) || !emailArg) return usage();
    if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");

    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        const email = normalize(emailArg);
        const emailHash = hashForLookup(email);
        const { rows: teachers } = await pool.query(
            "SELECT id, full_name, email_encrypted, email_hash, password_hash FROM users WHERE role = 'teacher' ORDER BY id"
        );

        const byHash = teachers.find((row) => row.email_hash === emailHash);
        const byEmail = teachers.find((row) => resolveEmailForApi(row.email_encrypted) === email);
        console.log(`Teachers in database:        ${teachers.length}`);
        console.log(`Found by email hash:         ${byHash ? `yes (id ${byHash.id})` : "no"}`);
        console.log(`Found by decrypted email:    ${byEmail ? `yes (id ${byEmail.id})` : "no"}`);

        const teacher = byHash || byEmail;
        if (!teacher) {
            for (const row of teachers) {
                const decrypted = resolveEmailForApi(row.email_encrypted);
                console.log(`  id ${row.id}: email ${decrypted ? `decrypts to ${decrypted}` : "does not decrypt with this ENCRYPTION_KEY"}`);
            }
            throw new Error(`No teacher account for ${email}`);
        }
        console.log(`Account:                     id ${teacher.id}, ${teacher.full_name}`);

        if (mode === "check") {
            const password = await ask("Password to check: ");
            const result = await verifyStoredPassword({
                inputPassword: password,
                storedHash: teacher.password_hash,
                legacyHashVerifier: hashExactForLookup,
                legacyDecryptor: tryDecrypt,
            });
            console.log(result.isValid ? "Password MATCHES the stored hash." : "Password does NOT match the stored hash.");
        } else {
            const password = await ask(`New password (at least ${MIN_PASSWORD_LENGTH} characters): `);
            const repeated = await ask("Repeat the new password: ");
            if (password !== repeated) throw new Error("The passwords do not match; nothing was changed.");
            if (password.length < MIN_PASSWORD_LENGTH) throw new Error("Password too short; nothing was changed.");
            await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [await hashPassword(password), teacher.id]);
            console.log("New password stored.");
        }

        if (teacher.email_hash !== emailHash) {
            await pool.query("UPDATE users SET email_hash = $1 WHERE id = $2", [emailHash, teacher.id]);
            console.log("Stored email hash did not match the email; fixed.");
        }
    } finally {
        if (prompt) prompt.close();
        await pool.end();
    }
};

main().catch((error) => {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
});
