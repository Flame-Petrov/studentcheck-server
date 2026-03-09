"use strict";

const fs = require("fs/promises");
const path = require("path");
const http = require("http");
const https = require("https");

const DEFAULT_REMOTE_BASE_URL = "https://studentcheck-server.onrender.com";
const REQUEST_TIMEOUT_MS = 120000;
const BACKUP_API_KEY = String(process.env.BACKUP_API_KEY || "");
const CLI_INPUT_ARGS = process.argv.slice(2).map((arg) => String(arg || "").trim()).filter(Boolean);
const ENV_INPUT_PATH = String(process.env.ENCRYPTED_INPUT || process.env.BACKUP_INPUT || "").trim();

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
                                `Decryption request failed (${res.statusCode || "unknown"}): ${raw.slice(0, 500)}`
                            )
                        );
                    }

                    try {
                        const parsed = raw ? JSON.parse(raw) : {};
                        resolve(parsed);
                    } catch (error) {
                        reject(new Error(`Decryption response is not valid JSON: ${error.message}`));
                    }
                });
            }
        );

        req.on("timeout", () => {
            req.destroy(new Error(`Decryption request timed out after ${REQUEST_TIMEOUT_MS}ms`));
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

const resolveEncryptedFilePath = async () => {
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
            `Encrypted input path not found. Tried: ${EXPLICIT_INPUT_CANDIDATES.join(" | ")}`
        );
    }

    const encryptedDir = path.join(process.cwd(), "encrypted_data");
    const entries = await fs.readdir(encryptedDir, { withFileTypes: true });
    const files = entries
        .filter((entry) => entry.isFile() && /\.js$/i.test(entry.name))
        .map((entry) => path.join(encryptedDir, entry.name));

    if (files.length === 0) {
        throw new Error("No encrypted backup file found. Provide a file path via ENCRYPTED_INPUT or script argument.");
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

const loadEncryptedObject = (encryptedFilePath) => {
    const resolvedModulePath = require.resolve(encryptedFilePath);
    delete require.cache[resolvedModulePath];
    const loaded = require(resolvedModulePath);

    if (!loaded || typeof loaded !== "object" || Array.isArray(loaded)) {
        throw new Error("Encrypted file must export an object");
    }
    if (typeof loaded.payload !== "string" || !loaded.payload.trim()) {
        throw new Error("Encrypted file does not contain a valid payload");
    }
    return loaded;
};

const createDecryptedFileContents = (payload) => {
    return [
        "\"use strict\";",
        "",
        `const decryptedBackup = ${JSON.stringify(payload, null, 2)};`,
        "",
        "module.exports = decryptedBackup;",
        "",
    ].join("\n");
};

const run = async () => {
    const encryptedFilePath = await resolveEncryptedFilePath();
    const encryptedData = loadEncryptedObject(encryptedFilePath);
    const headers = BACKUP_API_KEY ? { "x-backup-key": BACKUP_API_KEY } : {};

    let decryptedPayload = null;
    let successfulBaseUrl = null;
    const failures = [];

    for (const baseUrl of CANDIDATE_BASE_URLS) {
        const decryptUrl = new URL("/backup/decrypt", baseUrl).toString();
        try {
            decryptedPayload = await requestJson({
                method: "POST",
                urlString: decryptUrl,
                headers,
                body: { payload: encryptedData.payload },
            });
            successfulBaseUrl = baseUrl;
            break;
        } catch (error) {
            const reason = formatError(error);
            failures.push({ baseUrl, reason });
        }
    }

    if (!decryptedPayload || !successfulBaseUrl) {
        const summary = failures.map((f) => `${f.baseUrl} -> ${f.reason}`).join(" ; ");
        throw new Error(`All decryption endpoints failed. ${summary}`);
    }

    const backupData = decryptedPayload.backupData;
    if (!backupData || typeof backupData !== "object" || Array.isArray(backupData)) {
        throw new Error("Decryption response does not include valid backup data");
    }

    const existingMeta = (
        backupData.meta
        && typeof backupData.meta === "object"
        && !Array.isArray(backupData.meta)
    ) ? backupData.meta : {};

    const outputPayload = {
        ...backupData,
        meta: {
            ...existingMeta,
            decryptedAt: decryptedPayload.decryptedAt || new Date().toISOString(),
            decryptedBy: successfulBaseUrl,
            sourceEncryptedFile: path.basename(encryptedFilePath),
            keyReference: decryptedPayload.keyReference || encryptedData.keyReference || "unknown",
        },
    };

    const outputDir = path.join(process.cwd(), "decrypted_data");
    const outputFile = path.join(outputDir, `${createTimestamp()}.js`);

    await fs.mkdir(outputDir, { recursive: true });
    await fs.writeFile(outputFile, createDecryptedFileContents(outputPayload), "utf8");

};

run().catch((error) => {
    console.error("[DECRYPT] Failed:", formatError(error));
    console.error("[DECRYPT] Hint: make sure /backup/decrypt is deployed and BACKUP_API_KEY is set if required.");
    process.exitCode = 1;
});
