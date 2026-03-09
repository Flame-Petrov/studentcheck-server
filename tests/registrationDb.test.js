const assert = require("assert").strict;
const {
    mapRegistrationUniqueViolation,
    insertStudentWithIdCollisionRecovery,
} = require("../security/registrationDb");

const run = async (name, fn) => {
    try {
        await fn();
    } catch (err) {
        console.error(`FAIL: ${name}`);
        throw err;
    }
};

const runTests = async () => {
    await run("maps email/faculty/id unique violations by constraint name", async () => {
        assert.deepEqual(
            mapRegistrationUniqueViolation({ code: "23505", constraint: "uq_students_email_hash" }),
            { type: "duplicate_email", constraint: "uq_students_email_hash" }
        );
        assert.deepEqual(
            mapRegistrationUniqueViolation({ code: "23505", constraint: "uq_students_faculty_number_hash" }),
            { type: "duplicate_faculty_number", constraint: "uq_students_faculty_number_hash" }
        );
        assert.deepEqual(
            mapRegistrationUniqueViolation({ code: "23505", constraint: "students_pkey" }),
            { type: "id_collision", constraint: "students_pkey" }
        );
    });

    await run("insert path uses DB-generated id (sql omits explicit id column)", async () => {
        const calls = [];
        const pool = {
            async query(sql, values) {
                calls.push({ sql, values });
                return { rows: [{ id: 123 }] };
            },
        };

        const insertSql = "INSERT INTO students (full_name, email) VALUES ($1,$2) RETURNING id";
        await insertStudentWithIdCollisionRecovery({
            pool,
            insertSql,
            insertValues: ["Student Name", "encrypted-email"],
            requestId: "req-1",
        });

        assert.equal(calls.length, 1);
        assert.equal(calls[0].sql.includes("(id,"), false);
    });

    await run("id collision triggers one sequence resync and retries once", async () => {
        let count = 0;
        const queries = [];
        const pool = {
            async query(sql, values) {
                count += 1;
                queries.push(sql);
                if (count === 1) {
                    const err = new Error("duplicate key");
                    err.code = "23505";
                    err.constraint = "students_pkey";
                    throw err;
                }
                if (count === 2) {
                    assert.ok(sql.includes("setval"));
                    return { rows: [] };
                }
                return { rows: [{ id: 9 }] };
            },
        };

        const result = await insertStudentWithIdCollisionRecovery({
            pool,
            insertSql: "INSERT INTO students (full_name) VALUES ($1) RETURNING id",
            insertValues: ["Name"],
            requestId: "req-2",
            logger: { error: () => {} },
        });

        assert.equal(result.rows[0].id, 9);
        assert.equal(queries.length, 3);
    });
};

runTests().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
