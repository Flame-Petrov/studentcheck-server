"use strict";

const { Pool } = require("pg");

const APPLY = process.argv.includes("--apply");
const DERIVED_FILTER_SQL = "(joined_at IS NOT NULL OR left_at IS NOT NULL)";

const MISMATCH_QUERY = `
WITH derived AS (
    SELECT
        class_id,
        student_id,
        COUNT(DISTINCT session_key)::INTEGER AS derived_count
    FROM attendance_timestamps
    WHERE ${DERIVED_FILTER_SQL}
    GROUP BY class_id, student_id
),
combined AS (
    SELECT
        COALESCE(a.class_id, d.class_id) AS class_id,
        COALESCE(a.student_id, d.student_id) AS student_id,
        COALESCE(a.count, 0) AS summary_count,
        COALESCE(d.derived_count, 0) AS derived_count
    FROM attendances a
    FULL OUTER JOIN derived d
      ON d.class_id = a.class_id
     AND d.student_id = a.student_id
)
SELECT
    class_id,
    student_id,
    summary_count,
    derived_count
FROM combined
WHERE summary_count <> derived_count
ORDER BY class_id ASC, student_id ASC
`;

const buildPool = () => {
    if (!process.env.DATABASE_URL) {
        throw new Error("DATABASE_URL is required");
    }

    return new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
    });
};

const printMismatches = (rows, label) => {
    console.log(`[ATTENDANCE-RECONCILE] ${label}: ${rows.length} mismatches`);
    if (!rows.length) return;

    const previewRows = rows.slice(0, 50);
    console.table(previewRows);
    if (rows.length > previewRows.length) {
        console.log(`[ATTENDANCE-RECONCILE] ... ${rows.length - previewRows.length} more rows omitted from preview`);
    }
};

const applyReconciliation = async (client) => {
    await client.query(
        `
        WITH derived AS (
            SELECT
                class_id,
                student_id,
                COUNT(DISTINCT session_key)::INTEGER AS derived_count
            FROM attendance_timestamps
            WHERE ${DERIVED_FILTER_SQL}
            GROUP BY class_id, student_id
        )
        INSERT INTO attendances (class_id, student_id, count, timestamp)
        SELECT
            d.class_id,
            d.student_id,
            d.derived_count,
            NOW()
        FROM derived d
        ON CONFLICT (class_id, student_id)
        DO UPDATE SET
            count = EXCLUDED.count,
            timestamp = NOW()
        `
    );

    await client.query(
        `
        WITH derived AS (
            SELECT
                class_id,
                student_id,
                COUNT(DISTINCT session_key)::INTEGER AS derived_count
            FROM attendance_timestamps
            WHERE ${DERIVED_FILTER_SQL}
            GROUP BY class_id, student_id
        )
        UPDATE attendances a
        SET
            count = 0,
            timestamp = NOW()
        WHERE NOT EXISTS (
            SELECT 1
            FROM derived d
            WHERE d.class_id = a.class_id
              AND d.student_id = a.student_id
        )
          AND COALESCE(a.count, 0) <> 0
        `
    );
};

const run = async () => {
    const pool = buildPool();
    const client = await pool.connect();
    let transactionOpen = false;

    try {
        const before = await client.query(MISMATCH_QUERY);
        printMismatches(before.rows, "Before");

        if (!APPLY) {
            console.log("[ATTENDANCE-RECONCILE] Dry run complete. Use --apply to persist changes.");
            return;
        }

        await client.query("BEGIN");
        transactionOpen = true;
        await applyReconciliation(client);
        await client.query("COMMIT");
        transactionOpen = false;

        const after = await client.query(MISMATCH_QUERY);
        printMismatches(after.rows, "After");
        if (after.rows.length === 0) {
            console.log("[ATTENDANCE-RECONCILE] Verification passed: summary_count equals derived_history_count for all rows.");
        } else {
            console.log("[ATTENDANCE-RECONCILE] Verification failed: unresolved mismatches remain.");
            process.exitCode = 1;
        }
    } catch (error) {
        if (transactionOpen) {
            try {
                await client.query("ROLLBACK");
            } catch (rollbackError) {
                console.error("[ATTENDANCE-RECONCILE] Rollback failed:", rollbackError);
            }
        }
        throw error;
    } finally {
        client.release();
        await pool.end();
    }
};

run().catch((error) => {
    console.error("[ATTENDANCE-RECONCILE] Failed:", error && error.message ? error.message : error);
    process.exitCode = 1;
});
