"use strict";

const fs = require("fs/promises");
const path = require("path");
const http = require("http");
const https = require("https");

const DEFAULT_REMOTE_BASE_URL = "https://studentcheck-server.onrender.com";
const REQUEST_TIMEOUT_MS = 120000;
const BACKUP_API_KEY = String(process.env.BACKUP_API_KEY || "");
const ENV_INPUT_PATH = String(process.env.BACKUP_INPUT || process.env.TABLE_INPUT || "").trim();
const ENV_TABLE_NAME = String(process.env.TABLE_NAME || "").trim();
const ENV_APPEND_MODE = String(process.env.TABLE_LOAD_APPEND || "").toLowerCase() === "true";

const RAW_CLI_ARGS = process.argv.slice(2).map((arg) => String(arg || "").trim()).filter(Boolean);
const APPEND_FLAG = RAW_CLI_ARGS.includes("--append");
const CLI_ARGS = RAW_CLI_ARGS.filter((arg) => arg !== "--append");

const TABLE_NAME_REGEX = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

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
                                `Load-table request failed (${res.statusCode || "unknown"}): ${raw.slice(0, 500)}`
                            )
                        );
                    }

                    resolve(parsed);
                });
            }
        );

        req.on("timeout", () => {
            req.destroy(new Error(`Load-table request timed out after ${REQUEST_TIMEOUT_MS}ms`));
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

const pathExistsAsFile = async (candidatePath) => {
    try {
        const stat = await fs.stat(candidatePath);
        return stat.isFile();
    } catch {
        return false;
    }
};

const findLatestFile = async (directoryPath, fileMatcher) => {
    try {
        const entries = await fs.readdir(directoryPath, { withFileTypes: true });
        const files = entries
            .filter((entry) => entry.isFile() && fileMatcher(entry.name))
            .map((entry) => path.join(directoryPath, entry.name));

        if (files.length === 0) return null;

        const withStats = await Promise.all(
            files.map(async (filePath) => ({
                filePath,
                stat: await fs.stat(filePath),
            }))
        );

        withStats.sort((a, b) => b.stat.mtimeMs - a.stat.mtimeMs);
        return withStats[0].filePath;
    } catch {
        return null;
    }
};

const buildInputCandidates = () => {
    const candidates = [];
    if (ENV_INPUT_PATH) {
        candidates.push(ENV_INPUT_PATH);
    } else if (CLI_ARGS.length > 0) {
        const fileArgs = ENV_TABLE_NAME ? CLI_ARGS : CLI_ARGS.slice(0, -1);
        if (fileArgs.length > 0) {
            candidates.push(fileArgs.join(" "));
            candidates.push(fileArgs[0]);

            if (fileArgs.length > 1) {
                const lastArg = fileArgs[fileArgs.length - 1];
                candidates.push(lastArg);

                const firstArg = fileArgs[0];
                if (/[\\/]/.test(firstArg)) {
                    candidates.push(path.join(path.dirname(firstArg), lastArg));
                }
            }
        }
    }

    return Array.from(new Set(candidates.filter(Boolean)));
};

const resolveInputs = async () => {
    const tableName = ENV_TABLE_NAME || (CLI_ARGS.length > 1 ? CLI_ARGS[CLI_ARGS.length - 1] : "");
    if (!tableName || !TABLE_NAME_REGEX.test(tableName)) {
        throw new Error("Table name is required and must be a valid identifier. Usage: npm run db:load-table -- <filePath> <tableName>");
    }

    const inputCandidates = buildInputCandidates();
    for (const candidate of inputCandidates) {
        const resolved = path.isAbsolute(candidate)
            ? candidate
            : path.resolve(process.cwd(), candidate);

        if (await pathExistsAsFile(resolved)) {
            return { filePath: resolved, tableName };
        }
    }

    if (inputCandidates.length > 0) {
        throw new Error(`Input file path not found. Tried: ${inputCandidates.join(" | ")}`);
    }

    const latestDecrypted = await findLatestFile(
        path.join(process.cwd(), "decrypted_data"),
        (name) => /\.js$/i.test(name)
    );
    if (latestDecrypted) return { filePath: latestDecrypted, tableName };

    const latestBackup = await findLatestFile(
        path.join(process.cwd(), "backups"),
        (name) => /^database-backup-.*\.js$/i.test(name)
    );
    if (latestBackup) return { filePath: latestBackup, tableName };

    throw new Error("No input backup file found in decrypted_data/ or backups/.");
};

const loadFileModule = (filePath) => {
    const resolvedModulePath = require.resolve(filePath);
    delete require.cache[resolvedModulePath];
    return require(resolvedModulePath);
};

const normalizeTableEntry = (loaded, tableName) => {
    if (Array.isArray(loaded)) {
        return {
            rows: loaded,
            columns: [],
        };
    }

    if (!loaded || typeof loaded !== "object") {
        throw new Error("Input file must export an object or array");
    }

    if (loaded.tables && typeof loaded.tables === "object" && !Array.isArray(loaded.tables)) {
        const tableEntry = loaded.tables[tableName];
        if (tableEntry !== undefined) {
            if (Array.isArray(tableEntry)) {
                return { rows: tableEntry, columns: [] };
            }
            if (tableEntry && typeof tableEntry === "object" && Array.isArray(tableEntry.rows)) {
                return {
                    rows: tableEntry.rows,
                    columns: Array.isArray(tableEntry.columns) ? tableEntry.columns : [],
                };
            }
        }
    }

    if (loaded.tableName && Array.isArray(loaded.rows)) {
        return {
            rows: loaded.rows,
            columns: Array.isArray(loaded.columns) ? loaded.columns : [],
        };
    }

    if (Array.isArray(loaded.rows)) {
        return {
            rows: loaded.rows,
            columns: Array.isArray(loaded.columns) ? loaded.columns : [],
        };
    }

    if (Object.prototype.hasOwnProperty.call(loaded, tableName)) {
        const tableEntry = loaded[tableName];
        if (Array.isArray(tableEntry)) {
            return { rows: tableEntry, columns: [] };
        }
        if (tableEntry && typeof tableEntry === "object" && Array.isArray(tableEntry.rows)) {
            return {
                rows: tableEntry.rows,
                columns: Array.isArray(tableEntry.columns) ? tableEntry.columns : [],
            };
        }
    }

    throw new Error(`Could not resolve table data for "${tableName}" from input file.`);
};

const ensureRowsAreObjects = (rows) => {
    if (!Array.isArray(rows)) {
        throw new Error("Table rows must be an array");
    }

    rows.forEach((row, index) => {
        if (!row || typeof row !== "object" || Array.isArray(row)) {
            throw new Error(`Invalid row at index ${index}. Each row must be an object.`);
        }
    });
};

const loadTableFromFile = async ({ filePath, tableName, clearExisting }) => {
    const loaded = loadFileModule(filePath);
    const tableData = normalizeTableEntry(loaded, tableName);
    ensureRowsAreObjects(tableData.rows);

    const payload = {
        clearExisting,
        tables: {
            [tableName]: {
                columns: Array.isArray(tableData.columns) ? tableData.columns : [],
                rowCount: tableData.rows.length,
                rows: tableData.rows,
            },
        },
    };

    const headers = BACKUP_API_KEY ? { "x-backup-key": BACKUP_API_KEY } : {};
    const failures = [];
    let successfulBaseUrl = null;
    let responsePayload = null;

    for (const baseUrl of CANDIDATE_BASE_URLS) {
        const importUrl = new URL("/backup/import", baseUrl).toString();
        console.log(`[LOAD-TABLE] Trying ${importUrl}`);
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
            console.log(`[LOAD-TABLE] Attempt failed for ${baseUrl}: ${reason}`);
        }
    }

    if (!successfulBaseUrl || !responsePayload) {
        const summary = failures.map((item) => `${item.baseUrl} -> ${item.reason}`).join(" ; ");
        throw new Error(`All load-table endpoints failed. ${summary}`);
    }

    return {
        tableName,
        sourceFile: filePath,
        baseUrl: successfulBaseUrl,
        responsePayload,
    };
};

const run = async () => {
    const { filePath, tableName } = await resolveInputs();
    const clearExisting = !(APPEND_FLAG || ENV_APPEND_MODE);

    const result = await loadTableFromFile({
        filePath,
        tableName,
        clearExisting,
    });

    console.log(`[LOAD-TABLE] SUCCESS using ${result.baseUrl}`);
    console.log(`[LOAD-TABLE] Table: ${result.tableName}`);
    console.log(`[LOAD-TABLE] Source file: ${result.sourceFile}`);
    console.log(`[LOAD-TABLE] Mode: ${clearExisting ? "replace (clearExisting=true)" : "append (clearExisting=false)"}`);
    console.log(`[LOAD-TABLE] Inserted rows: ${result.responsePayload.insertedRows || 0}`);
    console.log(`[LOAD-TABLE] Added columns: ${(result.responsePayload.addedColumns || []).length}`);
};

run().catch((error) => {
    console.error("[LOAD-TABLE] Failed:", formatError(error));
    console.error("[LOAD-TABLE] Usage: npm run db:load-table -- <filePath> <tableName> [--append]");
    process.exitCode = 1;
});
