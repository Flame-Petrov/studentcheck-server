"use strict";

// Read-only: lists accounts that share an email address, so a duplicate can be
// resolved by hand. Prints to your terminal only; writes nothing and changes
// nothing. Needs DATABASE_URL, ENCRYPTION_KEY, LOOKUP_HASH_KEY in the env.
//
//   node scripts/findDuplicateEmails.js

const { Pool } = require("pg");
const { normalize, decrypt } = require("../security/cryptoService");
const { resolveEmailForApi } = require("../security/decryptors");

const tryDecrypt = (value) => {
    try {
        return decrypt(value);
    } catch {
        return null;
    }
};

const main = async () => {
    if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        const { rows } = await pool.query(`
            SELECT u.id, u.role, u.full_name, u.email_encrypted, u.created_at,
                   st.faculty_number_encrypted
            FROM users u
            LEFT JOIN students st ON st.user_id = u.id
            ORDER BY u.id
        `);

        const byEmail = new Map();
        for (const row of rows) {
            const email = resolveEmailForApi(row.email_encrypted);
            if (!email) continue;
            if (!byEmail.has(email)) byEmail.set(email, []);
            byEmail.get(email).push(row);
        }

        const duplicates = [...byEmail.entries()].filter(([, group]) => group.length > 1);
        if (duplicates.length === 0) {
            console.log("No two accounts share an email address.");
            return;
        }

        console.log(`${duplicates.length} email(s) are used by more than one account:\n`);
        for (const [email, group] of duplicates) {
            console.log(`${email}`);
            for (const row of group) {
                const facultyNumber = row.faculty_number_encrypted ? (tryDecrypt(row.faculty_number_encrypted) || "?") : "-";
                console.log(`    id ${row.id}  ${row.role.padEnd(7)}  faculty# ${String(facultyNumber).padEnd(12)}  created ${row.created_at.toISOString().slice(0, 10)}  ${row.full_name}`);
            }
            console.log("");
        }
        console.log("Decide which account to keep. To see a student's attendance before removing one, ask for a per-account query.");
    } finally {
        await pool.end();
    }
};

main().catch((error) => {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
});
