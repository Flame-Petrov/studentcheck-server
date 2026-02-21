"use strict";

const { encryptBackupObject, decryptBackupObject, encryptText } = require("./security/backupEncryptionService");

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

const encryptUserCredentialFieldsInBackup = (backupData) => {
    if (!backupData || typeof backupData !== "object" || Array.isArray(backupData)) {
        throw new Error("Invalid backup payload. Expected object.");
    }

    const hasTablesContainer = (
        backupData.tables
        && typeof backupData.tables === "object"
        && !Array.isArray(backupData.tables)
    );
    const sourceTables = hasTablesContainer ? backupData.tables : backupData;

    if (!sourceTables || typeof sourceTables !== "object" || Array.isArray(sourceTables)) {
        throw new Error("Backup payload does not contain tables.");
    }

    const encryptedTables = {};
    const tableStats = [];
    let totalRowsProcessed = 0;
    let emailFieldsEncrypted = 0;
    let passwordFieldsEncrypted = 0;
    let keyReference = process.env.BACKUP_ENCRYPTION_KEY ? "BACKUP_ENCRYPTION_KEY" : "ENCRYPTION_KEY";

    for (const [tableName, tableEntry] of Object.entries(sourceTables)) {
        const rows = Array.isArray(tableEntry)
            ? tableEntry
            : (tableEntry && typeof tableEntry === "object" && Array.isArray(tableEntry.rows) ? tableEntry.rows : null);

        if (!rows) {
            encryptedTables[tableName] = tableEntry;
            continue;
        }

        let tableEmailCount = 0;
        let tablePasswordCount = 0;
        const encryptedRows = rows.map((row) => {
            totalRowsProcessed += 1;
            if (!row || typeof row !== "object" || Array.isArray(row)) return row;

            const encryptedRow = { ...row };

            if (typeof encryptedRow.email === "string" && encryptedRow.email.trim()) {
                const encryptedEmail = encryptText(encryptedRow.email);
                encryptedRow.email = encryptedEmail.payload;
                keyReference = encryptedEmail.keyReference || keyReference;
                tableEmailCount += 1;
                emailFieldsEncrypted += 1;
            }

            if (typeof encryptedRow.password === "string" && encryptedRow.password.trim()) {
                const encryptedPassword = encryptText(encryptedRow.password);
                encryptedRow.password = encryptedPassword.payload;
                keyReference = encryptedPassword.keyReference || keyReference;
                tablePasswordCount += 1;
                passwordFieldsEncrypted += 1;
            }

            return encryptedRow;
        });

        if (Array.isArray(tableEntry)) {
            encryptedTables[tableName] = encryptedRows;
        } else {
            encryptedTables[tableName] = {
                ...tableEntry,
                rows: encryptedRows,
                rowCount: encryptedRows.length,
            };
        }

        tableStats.push({
            tableName,
            rows: rows.length,
            emailFieldsEncrypted: tableEmailCount,
            passwordFieldsEncrypted: tablePasswordCount,
        });
    }

    const transformedBackup = hasTablesContainer
        ? {
            ...backupData,
            meta: {
                ...(backupData.meta && typeof backupData.meta === "object" && !Array.isArray(backupData.meta)
                    ? backupData.meta
                    : {}),
                userFieldsEncryptedAt: new Date().toISOString(),
                userFieldsEncrypted: ["email", "password"],
            },
            tables: encryptedTables,
        }
        : encryptedTables;

    return {
        backupData: transformedBackup,
        keyReference,
        summary: {
            tablesProcessed: tableStats.length,
            totalRowsProcessed,
            emailFieldsEncrypted,
            passwordFieldsEncrypted,
            tableStats,
        },
    };
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

    const decryptBackup = async (req, res) => {
        logRequestStart(req);
        if (!validateBackupKey(req, res)) return;

        const encryptedPayload = req.body?.payload ?? req.body?.encryptedPayload ?? req.body;
        if (typeof encryptedPayload !== "string" || !encryptedPayload.trim()) {
            return res.status(400).send({ error: "Invalid encrypted payload" });
        }

        try {
            const decrypted = decryptBackupObject(encryptedPayload);
            return res.status(200).send({
                format: "studentcheck.decrypted-backup.v1",
                decryptedAt: new Date().toISOString(),
                keyReference: decrypted.keyReference,
                backupData: decrypted.data,
            });
        } catch (error) {
            console.error("[BACKUP] Decrypt failed:", error);
            return res.status(500).send({ error: "Backup decryption failed", details: error.message });
        }
    };

    const encryptUserFields = async (req, res) => {
        logRequestStart(req);
        if (!validateBackupKey(req, res)) return;

        const backupData = req.body?.backupData ?? req.body;
        if (!backupData || typeof backupData !== "object" || Array.isArray(backupData)) {
            return res.status(400).send({ error: "Invalid backupData payload" });
        }

        try {
            const encrypted = encryptUserCredentialFieldsInBackup(backupData);
            return res.status(200).send({
                format: "studentcheck.encrypted-user-fields.v1",
                encryptedAt: new Date().toISOString(),
                keyReference: encrypted.keyReference,
                algorithm: "aes-256-gcm",
                fields: ["email", "password"],
                summary: encrypted.summary,
                backupData: encrypted.backupData,
            });
        } catch (error) {
            console.error("[BACKUP] Encrypt user fields failed:", error);
            return res.status(500).send({ error: "User fields encryption failed", details: error.message });
        }
    };

    const dropEncryptionColumns = async (req, res) => {
        logRequestStart(req);
        if (!validateBackupKey(req, res)) return;

        const confirmation = String(req.body?.confirm || "");
        if (confirmation !== "DROP_ENCRYPTION_COLUMNS") {
            return res.status(400).send({
                error: "Confirmation required",
                required: "Set body.confirm = 'DROP_ENCRYPTION_COLUMNS'",
            });
        }

        const targetColumnsByTable = {
            students: ["email_encrypted", "email_hash", "faculty_number_encrypted", "faculty_number_hash"],
            teachers: ["email_encrypted", "email_hash"],
        };

        const indexesToDrop = [
            "idx_students_email_hash",
            "idx_students_faculty_number_hash",
            "idx_teachers_email_hash",
        ];

        const client = await pool.connect();
        try {
            const columnsBeforeDrop = [];
            for (const [tableName, columnNames] of Object.entries(targetColumnsByTable)) {
                const { rows } = await client.query(
                    `
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = $1
                      AND column_name = ANY($2::text[])
                    ORDER BY column_name ASC
                    `,
                    [tableName, columnNames]
                );
                rows.forEach((row) => {
                    columnsBeforeDrop.push({
                        table: tableName,
                        column: String(row.column_name),
                    });
                });
            }

            await client.query("BEGIN");

            await client.query(`
                ALTER TABLE students
                    DROP COLUMN IF EXISTS email_encrypted,
                    DROP COLUMN IF EXISTS email_hash,
                    DROP COLUMN IF EXISTS faculty_number_encrypted,
                    DROP COLUMN IF EXISTS faculty_number_hash;

                ALTER TABLE teachers
                    DROP COLUMN IF EXISTS email_encrypted,
                    DROP COLUMN IF EXISTS email_hash;
            `);

            for (const indexName of indexesToDrop) {
                await client.query(`DROP INDEX IF EXISTS ${quoteIdentifier(indexName)}`);
            }

            await client.query("COMMIT");

            return res.status(200).send({
                message: "Encryption/hash columns removed",
                removedColumns: columnsBeforeDrop,
                removedIndexes: indexesToDrop,
            });
        } catch (error) {
            await client.query("ROLLBACK");
            console.error("[MIGRATION] Drop encryption columns failed:", error);
            return res.status(500).send({
                error: "Failed to drop encryption/hash columns",
                details: error.message,
            });
        } finally {
            client.release();
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
        decryptBackup,
        encryptUserFields,
        dropEncryptionColumns,
        importBackup,
    };
};

module.exports = {
    createBackupHandlers,
};
