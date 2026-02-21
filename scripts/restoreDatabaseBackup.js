"use strict";

const fs = require("fs/promises");
const path = require("path");
const http = require("http");
const https = require("https");

const DEFAULT_REMOTE_BASE_URL = "https://studentcheck-server.onrender.com";
const REQUEST_TIMEOUT_MS = 60000;
const BACKUP_API_KEY = String(process.env.BACKUP_API_KEY || "");
const CLI_INPUT_PATH = process.argv[2] ? String(process.argv[2]).trim() : "";
const ENV_INPUT_PATH = String(process.env.BACKUP_INPUT || "").trim();
const INPUT_PATH = CLI_INPUT_PATH || ENV_INPUT_PATH;

const getCandidateBaseUrls = () => {
    const explicitBackupBaseUrl = String(process.env.BACKUP_BASE_URL || "").trim();
    if (explicitBackupBaseUrl) return [explicitBackupBaseUrl];

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

const requestJson = ({ method, urlString, headers = {}, body = null }) => {
    const url = new URL(urlString);
    const client = url.protocol === "https:" ? https : http;
    const bodyString = body == null ? "" : JSON.stringify(body);

    return new Promise((resolve, reject) => {
        const requestHeaders = {
            Accept: "application/json",
            ...headers,
        };

        if (body != null) {
            requestHeaders["Content-Type"] = "application/json";
            requestHeaders["Content-Length"] = Buffer.byteLength(bodyString);
        }

        const req = client.request(
            {
                protocol: url.protocol,
                hostname: url.hostname,
                port: url.port || undefined,
                path: `${url.pathname}${url.search}`,
                method,
                headers: requestHeaders,
                timeout: REQUEST_TIMEOUT_MS,
            },
            (res) => {
                let raw = "";
                res.setEncoding("utf8");
                res.on("data", (chunk) => {
                    raw += chunk;
                });
                res.on("end", () => {
                    let parsed = null;
                    try {
                        parsed = raw ? JSON.parse(raw) : {};
                    } catch {
                        parsed = { raw };
                    }

                    if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
                        return reject(
                            new Error(
                                `Restore request failed (${res.statusCode || "unknown"}): ${raw.slice(0, 500)}`
                            )
                        );
                    }

                    resolve(parsed);
                });
            }
        );

        req.on("timeout", () => {
            req.destroy(new Error(`Restore request timed out after ${REQUEST_TIMEOUT_MS}ms`));
        });
        req.on("error", (error) => {
            const details = [];
            if (error && error.message) details.push(error.message);
            if (error && Array.isArray(error.errors) && error.errors.length > 0) {
                for (const nested of error.errors) {
                    if (nested && nested.message) details.push(nested.message);
                }
            }
            reject(new Error(details.length > 0 ? details.join(" | ") : String(error)));
        });

        if (body != null) req.write(bodyString);
        req.end();
    });
};

const resolveBackupFilePath = async () => {
    if (INPUT_PATH) {
        return path.isAbsolute(INPUT_PATH)
            ? INPUT_PATH
            : path.resolve(process.cwd(), INPUT_PATH);
    }

    const backupsDir = path.join(process.cwd(), "backups");
    const dirEntries = await fs.readdir(backupsDir, { withFileTypes: true });
    const candidates = dirEntries
        .filter((entry) => entry.isFile() && /^database-backup-.*\.js$/i.test(entry.name))
        .map((entry) => path.join(backupsDir, entry.name));

    if (candidates.length === 0) {
        throw new Error("No backup file found. Provide path via BACKUP_INPUT or script argument.");
    }

    const withStats = await Promise.all(
        candidates.map(async (filePath) => ({
            filePath,
            stat: await fs.stat(filePath),
        }))
    );

    withStats.sort((a, b) => b.stat.mtimeMs - a.stat.mtimeMs);
    return withStats[0].filePath;
};

const loadPayloadFromBackupFile = (backupFilePath) => {
    const modulePath = require.resolve(backupFilePath);
    delete require.cache[modulePath];
    const loaded = require(modulePath);

    if (!loaded || typeof loaded !== "object") {
        throw new Error("Backup file must export an object");
    }

    if (loaded.tables && typeof loaded.tables === "object" && !Array.isArray(loaded.tables)) {
        return {
            clearExisting: true,
            tables: loaded.tables,
        };
    }

    if (loaded.tableName && Array.isArray(loaded.rows)) {
        const tableName = String(loaded.tableName);
        return {
            clearExisting: true,
            tables: {
                [tableName]: {
                    columns: Array.isArray(loaded.columns) ? loaded.columns : [],
                    rowCount: Number(loaded.rowCount || loaded.rows.length),
                    rows: loaded.rows,
                },
            },
        };
    }

    throw new Error("Unsupported backup file format. Expected full backup or single-table backup export.");
};

const run = async () => {
    const backupFilePath = await resolveBackupFilePath();
    console.log(`[RESTORE] Using backup file: ${backupFilePath}`);
    const payload = loadPayloadFromBackupFile(backupFilePath);

    const headers = BACKUP_API_KEY ? { "x-backup-key": BACKUP_API_KEY } : {};
    const failures = [];
    let successfulBaseUrl = null;
    let responsePayload = null;

    for (const baseUrl of CANDIDATE_BASE_URLS) {
        const importUrl = new URL("/backup/import", baseUrl).toString();
        console.log(`[RESTORE] Trying ${importUrl}`);
        try {
            responsePayload = await requestJson({
                method: "POST",
                urlString: importUrl,
                headers,
                body: payload,
            });
            successfulBaseUrl = baseUrl;
            break;
        } catch (error) {
            const reason = formatError(error);
            failures.push({ baseUrl, reason });
            console.log(`[RESTORE] Attempt failed for ${baseUrl}: ${reason}`);
        }
    }

    if (!successfulBaseUrl || !responsePayload) {
        const summary = failures.map((item) => `${item.baseUrl} -> ${item.reason}`).join(" ; ");
        throw new Error(`All restore endpoints failed. ${summary}`);
    }

    console.log(`[RESTORE] SUCCESS using ${successfulBaseUrl}`);
    console.log(
        `[RESTORE] Tables processed: ${responsePayload.tablesProcessed || 0}, cleared: ${responsePayload.clearedTables || 0}, inserted rows: ${responsePayload.insertedRows || 0}`
    );
    console.log(`[RESTORE] Created tables: ${(responsePayload.createdTables || []).join(", ") || "none"}`);
    const addedColumns = Array.isArray(responsePayload.addedColumns) ? responsePayload.addedColumns.length : 0;
    console.log(`[RESTORE] Added columns: ${addedColumns}`);
};

run().catch((error) => {
    console.error("[RESTORE] Failed:", formatError(error));
    console.error("[RESTORE] Hint: set BACKUP_BASE_URL and BACKUP_API_KEY if needed.");
    process.exitCode = 1;
});
