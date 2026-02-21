"use strict";

const fs = require("fs/promises");
const path = require("path");
const http = require("http");
const https = require("https");

const DEFAULT_REMOTE_BASE_URL = "https://studentcheck-server.onrender.com";
const REQUEST_TIMEOUT_MS = 120000;
const BACKUP_API_KEY = String(process.env.BACKUP_API_KEY || "");
const CLI_INPUT_ARGS = process.argv.slice(2).map((arg) => String(arg || "").trim()).filter(Boolean);
const ENV_INPUT_PATH = String(process.env.BACKUP_INPUT || process.env.DECRYPTED_INPUT || "").trim();

const buildExplicitInputCandidates = () => {
    const candidates = [];
    if (CLI_INPUT_ARGS.length > 0) {
        candidates.push(CLI_INPUT_ARGS.join(" "));
        candidates.push(CLI_INPUT_ARGS[0]);

        if (CLI_INPUT_ARGS.length > 1) {
            const lastArg = CLI_INPUT_ARGS[CLI_INPUT_ARGS.length - 1];
            candidates.push(lastArg);

            const firstArg = CLI_INPUT_ARGS[0];
            if (/[\\/]/.test(firstArg)) {
                candidates.push(path.join(path.dirname(firstArg), lastArg));
            }
        }
    }

    if (ENV_INPUT_PATH) {
        candidates.push(ENV_INPUT_PATH);
    }

    return Array.from(new Set(candidates.filter(Boolean)));
};

const EXPLICIT_INPUT_CANDIDATES = buildExplicitInputCandidates();

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
                    if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
                        return reject(
                            new Error(
                                `User fields encryption request failed (${res.statusCode || "unknown"}): ${raw.slice(0, 500)}`
                            )
                        );
                    }

                    try {
                        const parsed = raw ? JSON.parse(raw) : {};
                        resolve(parsed);
                    } catch (error) {
                        reject(new Error(`User fields encryption response is not valid JSON: ${error.message}`));
                    }
                });
            }
        );

        req.on("timeout", () => {
            req.destroy(new Error(`User fields encryption request timed out after ${REQUEST_TIMEOUT_MS}ms`));
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

const createTimestamp = () => new Date().toISOString().replace(/[:.]/g, "-");

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

const resolveInputBackupFilePath = async () => {
    for (const candidate of EXPLICIT_INPUT_CANDIDATES) {
        const resolved = path.isAbsolute(candidate)
            ? candidate
            : path.resolve(process.cwd(), candidate);

        if (await pathExistsAsFile(resolved)) {
            return resolved;
        }
    }

    if (EXPLICIT_INPUT_CANDIDATES.length > 0) {
        throw new Error(
            `Input backup path not found. Tried: ${EXPLICIT_INPUT_CANDIDATES.join(" | ")}`
        );
    }

    const latestDecrypted = await findLatestFile(
        path.join(process.cwd(), "decrypted_data"),
        (name) => /\.js$/i.test(name)
    );
    if (latestDecrypted) return latestDecrypted;

    const latestBackup = await findLatestFile(
        path.join(process.cwd(), "backups"),
        (name) => /^database-backup-.*\.js$/i.test(name)
    );
    if (latestBackup) return latestBackup;

    throw new Error("No input backup file found in decrypted_data/ or backups/.");
};

const normalizeBackupPayload = (loaded) => {
    if (!loaded || typeof loaded !== "object" || Array.isArray(loaded)) {
        throw new Error("Input file must export an object");
    }

    if (loaded.tables && typeof loaded.tables === "object" && !Array.isArray(loaded.tables)) {
        return loaded;
    }

    if (
        loaded.backupData
        && typeof loaded.backupData === "object"
        && !Array.isArray(loaded.backupData)
        && loaded.backupData.tables
        && typeof loaded.backupData.tables === "object"
        && !Array.isArray(loaded.backupData.tables)
    ) {
        return loaded.backupData;
    }

    if (loaded.tableName && Array.isArray(loaded.rows)) {
        const tableName = String(loaded.tableName);
        return {
            meta: {
                ...(loaded.meta && typeof loaded.meta === "object" && !Array.isArray(loaded.meta) ? loaded.meta : {}),
                source: "single-table-backup",
            },
            tables: {
                [tableName]: {
                    columns: Array.isArray(loaded.columns) ? loaded.columns : [],
                    rowCount: Number(loaded.rowCount || loaded.rows.length),
                    rows: loaded.rows,
                },
            },
        };
    }

    throw new Error("Unsupported backup format. Expected full backup data with tables.");
};

const loadBackupObject = (backupFilePath) => {
    const resolvedModulePath = require.resolve(backupFilePath);
    delete require.cache[resolvedModulePath];
    const loaded = require(resolvedModulePath);
    return normalizeBackupPayload(loaded);
};

const createOutputFileContents = (payload) => {
    return [
        "\"use strict\";",
        "",
        `const userFieldsEncryptedBackup = ${JSON.stringify(payload, null, 2)};`,
        "",
        "module.exports = userFieldsEncryptedBackup;",
        "",
    ].join("\n");
};

const run = async () => {
    const inputBackupFilePath = await resolveInputBackupFilePath();
    const backupData = loadBackupObject(inputBackupFilePath);
    const headers = BACKUP_API_KEY ? { "x-backup-key": BACKUP_API_KEY } : {};

    let responsePayload = null;
    let successfulBaseUrl = null;
    const failures = [];

    for (const baseUrl of CANDIDATE_BASE_URLS) {
        const encryptUrl = new URL("/backup/encrypt-user-fields", baseUrl).toString();
        console.log(`[ENCRYPT-USERS] Trying ${encryptUrl}`);
        try {
            responsePayload = await requestJson({
                method: "POST",
                urlString: encryptUrl,
                headers,
                body: { backupData },
            });
            successfulBaseUrl = baseUrl;
            break;
        } catch (error) {
            const reason = formatError(error);
            failures.push({ baseUrl, reason });
            console.log(`[ENCRYPT-USERS] Attempt failed for ${baseUrl}: ${reason}`);
        }
    }

    if (!responsePayload || !successfulBaseUrl) {
        const summary = failures.map((f) => `${f.baseUrl} -> ${f.reason}`).join(" ; ");
        throw new Error(`All user fields encryption endpoints failed. ${summary}`);
    }

    const encryptedBackupData = responsePayload.backupData;
    if (!encryptedBackupData || typeof encryptedBackupData !== "object" || Array.isArray(encryptedBackupData)) {
        throw new Error("User fields encryption response does not include valid backup data");
    }

    const existingMeta = (
        encryptedBackupData.meta
        && typeof encryptedBackupData.meta === "object"
        && !Array.isArray(encryptedBackupData.meta)
    ) ? encryptedBackupData.meta : {};

    const outputPayload = {
        ...encryptedBackupData,
        meta: {
            ...existingMeta,
            userFieldsEncryptedBy: successfulBaseUrl,
            sourceBackupFile: path.basename(inputBackupFilePath),
            keyReference: responsePayload.keyReference || existingMeta.keyReference || "unknown",
        },
    };

    const outputDir = path.join(process.cwd(), "encrypted_data", "user_fields");
    const outputFile = path.join(outputDir, `${createTimestamp()}.js`);

    await fs.mkdir(outputDir, { recursive: true });
    await fs.writeFile(outputFile, createOutputFileContents(outputPayload), "utf8");

    const summary = responsePayload.summary || {};
    console.log("[ENCRYPT-USERS] SUCCESS: user email/password fields encrypted.");
    console.log(`[ENCRYPT-USERS] Source file: ${inputBackupFilePath}`);
    console.log(`[ENCRYPT-USERS] Used server: ${successfulBaseUrl}`);
    console.log(`[ENCRYPT-USERS] Output file: ${outputFile}`);
    console.log(`[ENCRYPT-USERS] Tables processed: ${summary.tablesProcessed || 0}`);
    console.log(`[ENCRYPT-USERS] Email fields encrypted: ${summary.emailFieldsEncrypted || 0}`);
    console.log(`[ENCRYPT-USERS] Password fields encrypted: ${summary.passwordFieldsEncrypted || 0}`);
    console.log(`[ENCRYPT-USERS] Key reference: ${outputPayload.meta.keyReference}`);
};

run().catch((error) => {
    console.error("[ENCRYPT-USERS] Failed:", formatError(error));
    console.error("[ENCRYPT-USERS] Hint: make sure /backup/encrypt-user-fields is deployed and BACKUP_API_KEY is set if required.");
    process.exitCode = 1;
});
