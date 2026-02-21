"use strict";

const fs = require("fs/promises");
const path = require("path");
const http = require("http");
const https = require("https");

const BASE_URL = process.env.BACKUP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
const BACKUP_API_KEY = String(process.env.BACKUP_API_KEY || "");

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

        req.on("error", reject);
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

const createTimestamp = () => {
    return new Date().toISOString().replace(/[:.]/g, "-");
};

const run = async () => {
    const exportUrl = new URL("/backup/export", BASE_URL).toString();
    const headers = BACKUP_API_KEY ? { "x-backup-key": BACKUP_API_KEY } : {};

    console.log(`[BACKUP] Fetching snapshot from ${exportUrl}`);
    const payload = await requestJson(exportUrl, headers);

    const snapshot = {
        meta: {
            createdAt: new Date().toISOString(),
            source: BASE_URL,
            endpoint: "/backup/export",
            tableCount: Number(payload.table_count || 0),
        },
        tables: payload.tables || {},
    };

    const outputDir = path.join(process.cwd(), "backups");
    const outputFile = path.join(outputDir, `database-backup-${createTimestamp()}.js`);

    await fs.mkdir(outputDir, { recursive: true });
    await fs.writeFile(outputFile, createBackupFileContents(snapshot), "utf8");

    const tableNames = Object.keys(snapshot.tables);
    console.log("[BACKUP] SUCCESS: database backup file has been saved.");
    console.log(`[BACKUP] Backup saved to ${outputFile}`);
    console.log(`[BACKUP] Tables included (${tableNames.length}): ${tableNames.join(", ")}`);
};

run().catch((error) => {
    console.error("[BACKUP] Failed:", error.message);
    process.exitCode = 1;
});
