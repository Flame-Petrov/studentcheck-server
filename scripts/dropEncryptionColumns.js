"use strict";

const http = require("http");
const https = require("https");

const DEFAULT_REMOTE_BASE_URL = "https://studentcheck-server.onrender.com";
const REQUEST_TIMEOUT_MS = 60000;
const BACKUP_API_KEY = String(process.env.BACKUP_API_KEY || "");

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
                                `Drop columns request failed (${res.statusCode || "unknown"}): ${raw.slice(0, 500)}`
                            )
                        );
                    }

                    resolve(parsed);
                });
            }
        );

        req.on("timeout", () => {
            req.destroy(new Error(`Drop columns request timed out after ${REQUEST_TIMEOUT_MS}ms`));
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

const run = async () => {
    const headers = BACKUP_API_KEY ? { "x-backup-key": BACKUP_API_KEY } : {};
    const failures = [];
    let successfulBaseUrl = null;
    let responsePayload = null;

    for (const baseUrl of CANDIDATE_BASE_URLS) {
        const dropUrl = new URL("/backup/drop-encryption-columns", baseUrl).toString();
        try {
            responsePayload = await requestJson({
                method: "POST",
                urlString: dropUrl,
                headers,
                body: { confirm: "DROP_ENCRYPTION_COLUMNS" },
            });
            successfulBaseUrl = baseUrl;
            break;
        } catch (error) {
            const reason = formatError(error);
            failures.push({ baseUrl, reason });
        }
    }

    if (!successfulBaseUrl || !responsePayload) {
        const summary = failures.map((item) => `${item.baseUrl} -> ${item.reason}`).join(" ; ");
        throw new Error(`All drop-columns endpoints failed. ${summary}`);
    }

    const removedColumns = Array.isArray(responsePayload.removedColumns) ? responsePayload.removedColumns : [];
    const removedIndexes = Array.isArray(responsePayload.removedIndexes) ? responsePayload.removedIndexes : [];

    if (removedColumns.length > 0) {
    }
};

run().catch((error) => {
    console.error("[DROP-COLUMNS] Failed:", formatError(error));
    console.error("[DROP-COLUMNS] Hint: set BACKUP_BASE_URL/BACKUP_API_KEY and ensure the server has /backup/drop-encryption-columns.");
    process.exitCode = 1;
});
