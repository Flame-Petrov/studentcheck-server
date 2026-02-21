"use strict";

const fs = require("fs/promises");
const path = require("path");
const http = require("http");
const https = require("https");

const DEFAULT_REMOTE_BASE_URL = "https://studentcheck-server.onrender.com";
const REQUEST_TIMEOUT_MS = 120000;
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
                    if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
                        return reject(
                            new Error(
                                `Encryption request failed (${res.statusCode || "unknown"}): ${raw.slice(0, 500)}`
                            )
                        );
                    }

                    try {
                        const parsed = raw ? JSON.parse(raw) : {};
                        resolve(parsed);
                    } catch (error) {
                        reject(new Error(`Encryption response is not valid JSON: ${error.message}`));
                    }
                });
            }
        );

        req.on("timeout", () => {
            req.destroy(new Error(`Encryption request timed out after ${REQUEST_TIMEOUT_MS}ms`));
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

const resolveBackupFilePath = async () => {
    if (INPUT_PATH) {
        return path.isAbsolute(INPUT_PATH)
            ? INPUT_PATH
            : path.resolve(process.cwd(), INPUT_PATH);
    }

    const backupsDir = path.join(process.cwd(), "backups");
    const entries = await fs.readdir(backupsDir, { withFileTypes: true });
    const files = entries
        .filter((entry) => entry.isFile() && /^database-backup-.*\.js$/i.test(entry.name))
        .map((entry) => path.join(backupsDir, entry.name));

    if (files.length === 0) {
        throw new Error("No backup file found. Provide a file path via BACKUP_INPUT or script argument.");
    }

    const withStats = await Promise.all(
        files.map(async (filePath) => ({
            filePath,
            stat: await fs.stat(filePath),
        }))
    );
    withStats.sort((a, b) => b.stat.mtimeMs - a.stat.mtimeMs);
    return withStats[0].filePath;
};

const loadBackupObject = (backupFilePath) => {
    const resolvedModulePath = require.resolve(backupFilePath);
    delete require.cache[resolvedModulePath];
    const loaded = require(resolvedModulePath);

    if (!loaded || typeof loaded !== "object" || Array.isArray(loaded)) {
        throw new Error("Backup file must export an object");
    }
    return loaded;
};

const createEncryptedFileContents = (payload) => {
    return [
        "\"use strict\";",
        "",
        `const encryptedBackup = ${JSON.stringify(payload, null, 2)};`,
        "",
        "module.exports = encryptedBackup;",
        "",
    ].join("\n");
};

const run = async () => {
    const backupFilePath = await resolveBackupFilePath();
    const backupData = loadBackupObject(backupFilePath);
    const headers = BACKUP_API_KEY ? { "x-backup-key": BACKUP_API_KEY } : {};

    let encryptedPayload = null;
    let successfulBaseUrl = null;
    const failures = [];

    for (const baseUrl of CANDIDATE_BASE_URLS) {
        const encryptUrl = new URL("/backup/encrypt", baseUrl).toString();
        console.log(`[ENCRYPT] Trying ${encryptUrl}`);
        try {
            encryptedPayload = await requestJson({
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
            console.log(`[ENCRYPT] Attempt failed for ${baseUrl}: ${reason}`);
        }
    }

    if (!encryptedPayload || !successfulBaseUrl) {
        const summary = failures.map((f) => `${f.baseUrl} -> ${f.reason}`).join(" ; ");
        throw new Error(`All encryption endpoints failed. ${summary}`);
    }

    const outputDir = path.join(process.cwd(), "encrypted_data");
    const outputFile = path.join(outputDir, `${createTimestamp()}.js`);

    const outputPayload = {
        ...encryptedPayload,
        sourceFile: path.basename(backupFilePath),
        sourceEndpoint: successfulBaseUrl,
    };

    await fs.mkdir(outputDir, { recursive: true });
    await fs.writeFile(outputFile, createEncryptedFileContents(outputPayload), "utf8");

    console.log("[ENCRYPT] SUCCESS: backup data encrypted.");
    console.log(`[ENCRYPT] Source file: ${backupFilePath}`);
    console.log(`[ENCRYPT] Used server: ${successfulBaseUrl}`);
    console.log(`[ENCRYPT] Encrypted output: ${outputFile}`);
    console.log(`[ENCRYPT] Key reference: ${outputPayload.keyReference || "unknown"}`);
};

run().catch((error) => {
    console.error("[ENCRYPT] Failed:", formatError(error));
    console.error("[ENCRYPT] Hint: make sure Render service is reachable and BACKUP_API_KEY is set if required.");
    process.exitCode = 1;
});
