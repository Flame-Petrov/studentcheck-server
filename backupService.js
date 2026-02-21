"use strict";

const { encryptBackupObject } = require("./security/backupEncryptionService");

const BACKUP_IDENTIFIER_REGEX = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const BACKUP_COLUMN_TYPE_REGEX = /^[a-zA-Z0-9_\s(),[\]]+$/;

const quoteIdentifier = (identifier) => `"${String(identifier).replace(/"/g, "\"\"")}"`;

const ensureSafeIdentifier = (identifier, type) => {
    const value = String(identifier || "");
    if (!BACKUP_IDENTIFIER_REGEX.test(value)) {
        throw new Error(`Invalid ${type} identifier: ${value}`);
    }
    return value;
};

const sanitizeColumnType = (columnType) => {
    const normalized = String(columnType || "").trim().replace(/\s+/g, " ");
    if (!normalized) return null;
    if (!BACKUP_COLUMN_TYPE_REGEX.test(normalized)) return null;
    return normalized;
};

const looksLikeIsoTimestamp = (value) =>
    typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)
    && !Number.isNaN(Date.parse(value));

const inferColumnTypeFromRows = (rows, columnName) => {
    const values = [];
    for (const row of rows) {
        if (!row || typeof row !== "object" || Array.isArray(row)) continue;
        const value = row[columnName];
        if (value !== null && value !== undefined) values.push(value);
    }

    if (values.length === 0) return "TEXT";

    const hasArray = values.some((value) => Array.isArray(value));
    const hasObject = values.some((value) => value && typeof value === "object" && !Array.isArray(value));
    const hasBoolean = values.some((value) => typeof value === "boolean");
    const hasNumber = values.some((value) => typeof value === "number" && Number.isFinite(value));
    const hasString = values.some((value) => typeof value === "string");

    if (hasArray || hasObject) {
        if (!hasBoolean && !hasNumber && !hasString) return "JSONB";
        return "TEXT";
    }
    if (hasBoolean && !hasNumber && !hasString) return "BOOLEAN";
    if (hasNumber && !hasString && !hasBoolean) {
        const allIntegers = values.every((value) => typeof value === "number" && Number.isInteger(value));
        return allIntegers ? "BIGINT" : "DOUBLE PRECISION";
    }
    if (hasString && !hasNumber && !hasBoolean) {
        const allIso = values.every((value) => looksLikeIsoTimestamp(value));
        return allIso ? "TIMESTAMPTZ" : "TEXT";
    }
    return "TEXT";
};

const getRowsFromTableEntry = (tableEntry) => {
    if (tableEntry == null) return [];
    if (Array.isArray(tableEntry)) return tableEntry;
    if (typeof tableEntry === "object") {
        if (Array.isArray(tableEntry.rows)) return tableEntry.rows;
        return [];
    }
    throw new Error("Invalid table entry format in backup payload");
};

const getColumnsFromTableEntry = (tableEntry) => {
    if (!tableEntry || typeof tableEntry !== "object" || Array.isArray(tableEntry)) return [];
    if (!Array.isArray(tableEntry.columns)) return [];

    const columns = [];
    for (const rawColumn of tableEntry.columns) {
        if (!rawColumn || typeof rawColumn !== "object") continue;
        const rawName = rawColumn.name ?? rawColumn.column_name;
        const rawType = rawColumn.type ?? rawColumn.data_type;
        if (!rawName || !rawType) continue;
        const name = ensureSafeIdentifier(rawName, "column");
        const type = sanitizeColumnType(rawType) || "TEXT";
        columns.push({ name, type });
    }
    return columns;
};

const collectRowColumnNames = (rows) => {
    const columnSet = new Set();
    rows.forEach((row, rowIndex) => {
        if (!row || typeof row !== "object" || Array.isArray(row)) {
            throw new Error(`Invalid row at index ${rowIndex}. Each row must be an object.`);
        }
        Object.keys(row).forEach((columnName) => {
            columnSet.add(ensureSafeIdentifier(columnName, "column"));
        });
    });
    return Array.from(columnSet);
};

const normalizeBackupTablesPayload = (payload) => {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        throw new Error("Invalid backup payload. Expected object.");
    }

    const source = (
        payload.tables
        && typeof payload.tables === "object"
        && !Array.isArray(payload.tables)
    ) ? payload.tables : payload;

    const normalized = {};
    for (const [rawTableName, tableEntry] of Object.entries(source)) {
        const tableName = ensureSafeIdentifier(rawTableName, "table");
        normalized[tableName] = {
            rows: getRowsFromTableEntry(tableEntry),
            columns: getColumnsFromTableEntry(tableEntry),
        };
    }
    return normalized;
};

const normalizeInsertValue = (value) => {
    if (value === undefined || value === null) return null;
    if (value instanceof Date) return value.toISOString();
    if (typeof value === "object") return JSON.stringify(value);
    return value;
};

const validateBackupKey = (req, res) => {
    const configuredBackupKey = String(process.env.BACKUP_API_KEY || "");
    if (!configuredBackupKey) return true;

    const providedBackupKey = String(req.headers["x-backup-key"] || "");
    if (!providedBackupKey || providedBackupKey !== configuredBackupKey) {
        res.status(401).send({ error: "Unauthorized backup request" });
        return false;
    }
    return true;
};

const createBackupSnapshot = async (pool) => {
    const { rows: tableRows } = await pool.query(`
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
        ORDER BY tablename ASC
    `);

    const tables = {};

    for (const row of tableRows) {
        const tableName = String(row.tablename);
        const quotedTableName = quoteIdentifier(tableName);

        const [tableResult, columnResult] = await Promise.all([
            pool.query(`SELECT * FROM ${quotedTableName}`),
            pool.query(
                `
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = $1
                ORDER BY ordinal_position ASC
                `,
                [tableName]
            ),
        ]);

        tables[tableName] = {
            rowCount: tableResult.rows.length,
            columns: columnResult.rows.map((column) => ({
                name: column.column_name,
                type: column.data_type,
                nullable: column.is_nullable === "YES",
                defaultValue: column.column_default,
            })),
            rows: tableResult.rows,
        };
    }

    return {
        generated_at: new Date().toISOString(),
        table_count: tableRows.length,
        tables,
    };
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

const createBackupFilename = () => {
    return `database-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.js`;
};

const createBackupHandlers = ({ pool, logRequestStart }) => {
    const exportBackup = async (req, res) => {
        logRequestStart(req, { includeBody: false });
        if (!validateBackupKey(req, res)) return;

        try {
            const snapshot = await createBackupSnapshot(pool);
            return res.status(200).send(snapshot);
        } catch (error) {
            console.error("[BACKUP] Export failed:", error);
            return res.status(500).send({ error: "Internal server error" });
        }
    };

    const downloadBackup = async (req, res) => {
        logRequestStart(req, { includeBody: false });
        if (!validateBackupKey(req, res)) return;

        try {
            const snapshot = await createBackupSnapshot(pool);
            const fileName = createBackupFilename();
            const fileContents = createBackupFileContents(snapshot);

            res.setHeader("Content-Type", "application/javascript; charset=utf-8");
            res.setHeader("Content-Disposition", `attachment; filename=\"${fileName}\"`);
            return res.status(200).send(fileContents);
        } catch (error) {
            console.error("[BACKUP] Download failed:", error);
            return res.status(500).send({ error: "Internal server error" });
        }
    };

    const encryptBackup = async (req, res) => {
        logRequestStart(req);
        if (!validateBackupKey(req, res)) return;

        const backupData = req.body?.backupData ?? req.body;
        if (!backupData || typeof backupData !== "object" || Array.isArray(backupData)) {
            return res.status(400).send({ error: "Invalid backupData payload" });
        }

        try {
            const encrypted = encryptBackupObject(backupData);
            return res.status(200).send({
                format: "studentcheck.encrypted-backup.v1",
                encryptedAt: new Date().toISOString(),
                algorithm: encrypted.algorithm,
                keyReference: encrypted.keyReference,
                payload: encrypted.payload,
            });
        } catch (error) {
            console.error("[BACKUP] Encrypt failed:", error);
            return res.status(500).send({ error: "Backup encryption failed", details: error.message });
        }
    };

    const importBackup = async (req, res) => {
        logRequestStart(req);
        if (!validateBackupKey(req, res)) return;

        let backupTables;
        try {
            backupTables = normalizeBackupTablesPayload(req.body || {});
        } catch (error) {
            return res.status(400).send({ error: error.message });
        }

        const tableNames = Object.keys(backupTables);
        if (tableNames.length === 0) {
            return res.status(400).send({ error: "No tables provided for backup import" });
        }

        const clearExisting = req.body?.clearExisting !== false;
        const importStats = {
            tablesProcessed: tableNames.length,
            clearedTables: 0,
            createdTables: [],
            addedColumns: [],
            insertedRows: 0,
        };

        const client = await pool.connect();
        try {
            await client.query("BEGIN");

            const { rows: existingTableRows } = await client.query(`
                SELECT tablename
                FROM pg_tables
                WHERE schemaname = 'public'
            `);
            const existingTables = new Set(existingTableRows.map((row) => String(row.tablename)));

            for (const tableName of tableNames) {
                const tableData = backupTables[tableName];
                const rowColumnNames = collectRowColumnNames(tableData.rows);
                const declaredColumns = new Map(tableData.columns.map((column) => [column.name, column]));
                const allColumnNames = Array.from(new Set([...declaredColumns.keys(), ...rowColumnNames]));

                if (!existingTables.has(tableName)) {
                    if (allColumnNames.length === 0) {
                        await client.query(
                            `CREATE TABLE IF NOT EXISTS ${quoteIdentifier(tableName)} (_backup_placeholder TEXT)`
                        );
                    } else {
                        const columnDefs = allColumnNames.map((columnName) => {
                            const declaredType = declaredColumns.get(columnName)?.type;
                            const columnType = sanitizeColumnType(declaredType)
                                || inferColumnTypeFromRows(tableData.rows, columnName);
                            return `${quoteIdentifier(columnName)} ${columnType}`;
                        });
                        await client.query(
                            `CREATE TABLE IF NOT EXISTS ${quoteIdentifier(tableName)} (${columnDefs.join(", ")})`
                        );
                    }

                    existingTables.add(tableName);
                    importStats.createdTables.push(tableName);
                } else if (allColumnNames.length > 0) {
                    const { rows: existingColumnRows } = await client.query(
                        `
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_schema = 'public' AND table_name = $1
                        `,
                        [tableName]
                    );
                    const existingColumns = new Set(existingColumnRows.map((row) => String(row.column_name)));

                    for (const columnName of allColumnNames) {
                        if (existingColumns.has(columnName)) continue;

                        const declaredType = declaredColumns.get(columnName)?.type;
                        const columnType = sanitizeColumnType(declaredType)
                            || inferColumnTypeFromRows(tableData.rows, columnName);

                        await client.query(
                            `
                            ALTER TABLE ${quoteIdentifier(tableName)}
                            ADD COLUMN IF NOT EXISTS ${quoteIdentifier(columnName)} ${columnType}
                            `
                        );
                        importStats.addedColumns.push({
                            table: tableName,
                            column: columnName,
                            type: columnType,
                        });
                    }
                }

                backupTables[tableName].insertColumns = rowColumnNames;
            }

            if (clearExisting) {
                const truncateTargets = tableNames.map((tableName) => quoteIdentifier(tableName));
                await client.query(`TRUNCATE TABLE ${truncateTargets.join(", ")} RESTART IDENTITY CASCADE`);
                importStats.clearedTables = truncateTargets.length;
            }

            for (const tableName of tableNames) {
                const tableData = backupTables[tableName];
                const rows = tableData.rows;
                const insertColumns = tableData.insertColumns || [];
                if (rows.length === 0 || insertColumns.length === 0) continue;

                const quotedColumns = insertColumns.map((column) => quoteIdentifier(column)).join(", ");
                const valuePlaceholders = insertColumns.map((_, idx) => `$${idx + 1}`).join(", ");
                const insertSql = `
                    INSERT INTO ${quoteIdentifier(tableName)} (${quotedColumns})
                    VALUES (${valuePlaceholders})
                `;

                for (const row of rows) {
                    const values = insertColumns.map((column) => normalizeInsertValue(row[column]));
                    await client.query(insertSql, values);
                    importStats.insertedRows += 1;
                }
            }

            await client.query("COMMIT");
            return res.status(200).send({
                message: "Backup import completed",
                ...importStats,
            });
        } catch (error) {
            await client.query("ROLLBACK");
            console.error("[BACKUP] Import failed:", error);
            return res.status(500).send({ error: "Backup import failed", details: error.message });
        } finally {
            client.release();
        }
    };

    return {
        exportBackup,
        downloadBackup,
        encryptBackup,
        importBackup,
    };
};

module.exports = {
    createBackupHandlers,
};
