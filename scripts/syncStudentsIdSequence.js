const { Pool } = require("pg");

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

const run = async () => {
    const sql = `
        SELECT setval(
            pg_get_serial_sequence('students', 'id'),
            COALESCE((SELECT MAX(id) FROM students), 1),
            true
        ) AS new_sequence_value
    `;
    const { rows } = await pool.query(sql);
};

run()
    .catch((err) => {
        console.error("Failed to sync students.id sequence", err);
        process.exitCode = 1;
    })
    .finally(async () => {
        await pool.end();
    });
