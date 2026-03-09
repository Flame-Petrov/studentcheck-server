const assert = require("assert").strict;
const crypto = require("crypto");
const { buildPostClassStudentsHandler } = require("../security/classStudentsPostHandler");

const normalize = (value) =>
    typeof value === "string" ? value.trim().toLowerCase() : String(value || "").trim().toLowerCase();

const hashForLookup = (value) =>
    crypto.createHash("sha256").update(normalize(value), "utf8").digest("hex");

const run = async (name, fn) => {
    try {
        await fn();
    } catch (err) {
        console.error(`FAIL: ${name}`);
        throw err;
    }
};

const createRes = () => {
    const out = {
        statusCode: 200,
        body: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        send(payload) {
            this.body = payload;
            return this;
        },
    };
    return out;
};

const makeHandler = ({ classesById = {}, teacherByEmail = {}, addStudentsToClass } = {}) => {
    const pool = {
        async query(sql, values) {
            if (sql.includes("FROM teachers WHERE email_hash")) {
                const id = teacherByEmail[values[0]];
                return { rows: id ? [{ id }] : [] };
            }
            if (sql.includes("FROM classes WHERE id = $1")) {
                const cls = classesById[Number(values[0])];
                return { rows: cls ? [{ id: cls.id, teacher_id: cls.teacher_id }] : [] };
            }
            throw new Error(`Unexpected SQL: ${sql}`);
        },
    };

    return buildPostClassStudentsHandler({
        pool,
        normalize,
        hashForLookup,
        addStudentsToClass: addStudentsToClass || (async () => ({ assignedCount: 1 })),
        logger: { log: () => {}, error: () => {} },
    });
};

const runTests = async () => {
    await run("success path (owner teacher)", async () => {
        const handler = makeHandler({
            classesById: { 8: { id: 8, teacher_id: 7 } },
            addStudentsToClass: async (classId, students) => {
                assert.equal(classId, 8);
                assert.equal(students.length, 1);
                return { assignedCount: 1 };
            },
        });
        const req = {
            query: { class_id: "8" },
            body: { students: [{ faculty_number: "381222005" }], teacherEmail: "fallback@example.com" },
            authTeacherId: 7,
            user: { email: "Teacher@Example.com" },
        };
        const res = createRes();
        await handler(req, res);
        assert.equal(res.statusCode, 200);
        assert.deepEqual(res.body, { success: true, classId: 8, addedCount: 1 });
    });

    await run("wrong owner => 403", async () => {
        const handler = makeHandler({
            classesById: { 8: { id: 8, teacher_id: 9 } },
        });
        const req = {
            query: { class_id: "8" },
            body: { students: [{ facultyNumber: "381222005" }] },
            authTeacherId: 7,
            user: { email: "teacher@example.com" },
        };
        const res = createRes();
        await handler(req, res);
        assert.equal(res.statusCode, 403);
    });

    await run("missing class_id => 400", async () => {
        const handler = makeHandler();
        const req = {
            query: {},
            body: { students: [{ faculty_number: "381222005" }] },
            authTeacherId: 7,
            user: { email: "teacher@example.com" },
        };
        const res = createRes();
        await handler(req, res);
        assert.equal(res.statusCode, 400);
    });

    await run("invalid token context => 401", async () => {
        const handler = makeHandler({
            classesById: { 8: { id: 8, teacher_id: 7 } },
        });
        const req = {
            query: { class_id: "8" },
            body: { students: [{ faculty_number: "381222005" }] },
            user: {},
        };
        const res = createRes();
        await handler(req, res);
        assert.equal(res.statusCode, 401);
        assert.deepEqual(res.body, { error: "Invalid or expired token" });
    });

    await run("class not found => 404", async () => {
        const handler = makeHandler();
        const req = {
            query: { class_id: "999" },
            body: { students: [{ faculty_number: "381222005" }] },
            authTeacherId: 7,
            user: { email: "teacher@example.com" },
        };
        const res = createRes();
        await handler(req, res);
        assert.equal(res.statusCode, 404);
    });
};

runTests().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
