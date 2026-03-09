"use strict";

const fs = require("fs/promises");
const path = require("path");
const { Pool } = require("pg");
const { encryptRaw, hashForLookup } = require("../security/cryptoService");
const { resolveEmailForApi } = require("../security/decryptors");

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const APPLY = process.argv.includes("--apply");
const SKIP_REPORT = process.argv.includes("--no-report");

const normalizePlainEmail = (value) => {
    const raw = String(value || "").trim();
    if (!raw) return null;
    if (!EMAIL_REGEX.test(raw)) return null;
    return raw.toLowerCase();
};

const previewValue = (value) => {
    if (typeof value !== "string") return null;
    const trimmed = value.trim();
    if (!trimmed) return null;
    const normalized = normalizePlainEmail(trimmed);
    if (!normalized) return `[len:${trimmed.length}]`;

    const [localPart, domain] = normalized.split("@");
    const visible = localPart.slice(0, 2);
    return `${visible}***@${domain}`;
};

const nowStamp = () => new Date().toISOString().replace(/[:.]/g, "-");

const buildUpdateStatement = (updates, id) => {
    const keys = Object.keys(updates);
    if (keys.length === 0) return null;

    const setSql = keys.map((field, idx) => `${field} = $${idx + 1}`).join(", ");
    const values = keys.map((key) => updates[key]);
    values.push(id);

    return {
        sql: `UPDATE students SET ${setSql} WHERE id = $${keys.length + 1}`,
        values,
    };
};

const run = async () => {
    if (!process.env.DATABASE_URL) {
        throw new Error("DATABASE_URL is required");
    }

    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
    });

    const summary = {
        mode: APPLY ? "apply" : "dry-run",
        totalRows: 0,
        plainValidEmailRows: 0,
        encryptedOrMixedDecryptableRows: 0,
        missingEmailRows: 0,
        undecodableRows: 0,
        rowsNeedingMetadataBackfill: 0,
        metadataRowsUpdated: 0,
    };

    const manualRepairRows = [];
    const pendingUpdates = [];

    try {
        const { rows } = await pool.query(
            `
            SELECT
                id,
                email,
                email_encrypted,
                email_hash
            FROM students
            ORDER BY id ASC
            `
        );
        summary.totalRows = rows.length;

        for (const row of rows) {
            const emailRaw = row.email;
            const emailEncryptedRaw = row.email_encrypted;
            const plainFromEmail = normalizePlainEmail(emailRaw);
            const plainFromEncryptedColumn = normalizePlainEmail(emailEncryptedRaw);
            const resolvedEmail = resolveEmailForApi(emailRaw) || resolveEmailForApi(emailEncryptedRaw);
            const hasAnySource = Boolean(
                (typeof emailRaw === "string" && emailRaw.trim())
                || (typeof emailEncryptedRaw === "string" && emailEncryptedRaw.trim())
            );

            if (!hasAnySource) {
                summary.missingEmailRows += 1;
                continue;
            }

            if (!resolvedEmail) {
                summary.undecodableRows += 1;
                manualRepairRows.push({
                    id: row.id,
                    emailPreview: previewValue(emailRaw),
                    emailEncryptedPreview: previewValue(emailEncryptedRaw),
                });
                continue;
            }

            if (plainFromEmail || plainFromEncryptedColumn) {
                summary.plainValidEmailRows += 1;
            } else {
                summary.encryptedOrMixedDecryptableRows += 1;
            }

            const updates = {};
            if (!row.email_hash) {
                updates.email_hash = hashForLookup(resolvedEmail);
            }

            if (!row.email_encrypted) {
                if (plainFromEmail) {
                    updates.email_encrypted = encryptRaw(resolvedEmail);
                } else if (resolveEmailForApi(emailRaw)) {
                    updates.email_encrypted = emailRaw;
                }
            }

            const updateStatement = buildUpdateStatement(updates, row.id);
            if (updateStatement) {
                summary.rowsNeedingMetadataBackfill += 1;
                pendingUpdates.push(updateStatement);
            }
        }

        if (APPLY && pendingUpdates.length > 0) {
            const client = await pool.connect();
            try {
                await client.query("BEGIN");
                for (const statement of pendingUpdates) {
                    await client.query(statement.sql, statement.values);
                    summary.metadataRowsUpdated += 1;
                }
                await client.query("COMMIT");
            } catch (error) {
                await client.query("ROLLBACK");
                throw error;
            } finally {
                client.release();
            }
        }

        if (!SKIP_REPORT) {
            const report = {
                generatedAt: new Date().toISOString(),
                summary,
                manualRepairRows,
            };
            const reportDir = path.join(process.cwd(), "backups");
            const reportPath = path.join(reportDir, `mixed-student-email-backfill-report-${nowStamp()}.json`);
            await fs.mkdir(reportDir, { recursive: true });
            await fs.writeFile(reportPath, JSON.stringify(report, null, 2), "utf8");
        }
    } finally {
        await pool.end();
    }
};

run().catch((error) => {
    console.error("[MIXED-EMAIL-BACKFILL] Failed:", error && error.message ? error.message : error);
    process.exitCode = 1;
});
