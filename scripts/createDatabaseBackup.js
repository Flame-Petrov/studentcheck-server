"use strict";

const fs = require("fs/promises");
const path = require("path");
const http = require("http");
const https = require("https");

const DEFAULT_REMOTE_BASE_URL = "https://studentcheck-server.onrender.com";

const getCandidateBaseUrls = () => {
    const explicitBackupBaseUrl = String(process.env.BACKUP_BASE_URL || "").trim();
    if (explicitBackupBaseUrl) {
        return [explicitBackupBaseUrl];
    }

    const port = process.env.PORT || 3000;
    const candidates = [
        String(process.env.RENDER_EXTERNAL_URL || "").trim(),
        String(process.env.APP_URL || "").trim(),
        DEFAULT_REMOTE_BASE_URL,
        `http://127.0.0.1:${port}`,
        `http://localhost:${port}`,
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ].filter(Boolean);

    return Array.from(new Set(candidates));
};

const CANDIDATE_BASE_URLS = getCandidateBaseUrls();
const BACKUP_API_KEY = String(process.env.BACKUP_API_KEY || "");
const REQUEST_TIMEOUT_MS = 30000;

const requestJson = (urlString, headers = {}) => {
    const url = new URL(urlString);
    const client = url.protocol === "https:" ? https : http;

    return new Promise((resolve, reject) => {
        const req = client.request(
            {
                protocol: url.protocol,
                hostname: url.hostname,
                port: url.port || undefined,
                path: `${url.pathname}${url.search}`,
                method: "GET",
                headers: {
                    Accept: "application/json",
                    ...headers,
                },
                timeout: REQUEST_TIMEOUT_MS,
            },
            (res) => {
                let raw = "";
                res.setEncoding("utf8");
                res.on("data", (chunk) => {
                    raw += chunk;
                });
                res.on("end", () => {
                    if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
                        return reject(
                            new Error(
                                `Backup request failed (${res.statusCode || "unknown"}): ${raw.slice(0, 500)}`
                            )
                        );
                    }

                    try {
                        const parsed = JSON.parse(raw);
                        resolve(parsed);
                    } catch (error) {
                        reject(new Error(`Backup response is not valid JSON: ${error.message}`));
                    }
                });
            }
        );

        req.on("timeout", () => {
            req.destroy(new Error(`Backup request timed out after ${REQUEST_TIMEOUT_MS}ms`));
        });
        req.on("error", (error) => {
            const details = [];
            if (error && error.message) {
                details.push(error.message);
            }
            if (error && Array.isArray(error.errors) && error.errors.length > 0) {
                for (const nested of error.errors) {
                    if (nested && nested.message) {
                        details.push(nested.message);
                    }
                }
            }
            const message = details.length > 0 ? details.join(" | ") : String(error);
            reject(new Error(`Backup request network error: ${message}`));
        });
        req.end();
    });
};

const createBackupFileContents = (snapshot) => {
    return [
        "\"use strict\";",
        "",
        `const databaseBackup = ${JSON.stringify(snapshot, null, 2)};`,
        "",
        "module.exports = databaseBackup;",
        "",
    ].join("\n");
};

const sanitizeFileSegment = (value) => {
    return String(value || "")
        .trim()
        .replace(/[^a-zA-Z0-9._-]/g, "_");
};

const createTableBackupFileContents = (tableName, tableSnapshot, meta) => {
    const payload = {
        meta,
        tableName,
        columns: Array.isArray(tableSnapshot?.columns) ? tableSnapshot.columns : [],
        rowCount: Number(tableSnapshot?.rowCount || 0),
        rows: Array.isArray(tableSnapshot?.rows) ? tableSnapshot.rows : [],
    };

    return [
        "\"use strict\";",
        "",
        `const tableBackup = ${JSON.stringify(payload, null, 2)};`,
        "",
        "module.exports = tableBackup;",
        "",
    ].join("\n");
};

const createTimestamp = () => {
    return new Date().toISOString().replace(/[:.]/g, "-");
};

const formatError = (error) => {
    if (!error) return "Unknown error";
    if (error instanceof Error && error.message) return error.message;
    if (typeof error === "string" && error.trim()) return error;
    try {
        return JSON.stringify(error);
    } catch {
        return String(error);
    }
};

const run = async () => {
    const headers = BACKUP_API_KEY ? { "x-backup-key": BACKUP_API_KEY } : {};
    let payload = null;
    let successfulBaseUrl = null;
    const failures = [];

    for (const baseUrl of CANDIDATE_BASE_URLS) {
        const exportUrl = new URL("/backup/export", baseUrl).toString();
        try {
            payload = await requestJson(exportUrl, headers);
            successfulBaseUrl = baseUrl;
            break;
        } catch (error) {
            const reason = formatError(error);
            failures.push({ baseUrl, reason });
        }
    }

    if (!payload || !successfulBaseUrl) {
        const summary = failures.map((f) => `${f.baseUrl} -> ${f.reason}`).join(" ; ");
        throw new Error(`All backup endpoints failed. ${summary}`);
    }


    const snapshot = {
        meta: {
            createdAt: new Date().toISOString(),
            source: successfulBaseUrl,
            endpoint: "/backup/export",
            tableCount: Number(payload.table_count || 0),
        },
        tables: payload.tables || {},
    };

    const outputDir = path.join(process.cwd(), "backups");
    const outputFile = path.join(outputDir, `database-backup-${createTimestamp()}.js`);

    await fs.mkdir(outputDir, { recursive: true });
    await fs.writeFile(outputFile, createBackupFileContents(snapshot), "utf8");

    const backupBaseName = path.basename(outputFile, ".js");
    const perTableDir = path.join(outputDir, backupBaseName);
    await fs.mkdir(perTableDir, { recursive: true });

    const tableNames = Object.keys(snapshot.tables);
    for (const tableName of tableNames) {
        const safeTableName = sanitizeFileSegment(tableName);
        const tableOutputFile = path.join(perTableDir, `${safeTableName}.js`);
        const tableSnapshot = snapshot.tables[tableName] || { rowCount: 0, rows: [] };

        await fs.writeFile(
            tableOutputFile,
            createTableBackupFileContents(tableName, tableSnapshot, snapshot.meta),
            "utf8"
        );
    }

};

run().catch((error) => {
    console.error("[BACKUP] Failed:", formatError(error));
    console.error("[BACKUP] Hint: set BACKUP_BASE_URL if you want a specific endpoint.");
    process.exitCode = 1;
});
