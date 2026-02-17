const PORT = process.env.PORT || 3000;
const DATABASE_URL = "postgresql://postgres:Flame-Supabase01!@db.imnqwnpsuapkbbnuufqn.supabase.co:5432/postgres";

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg"); // PostgreSQL client
const Stripe = require("stripe");
const { createDbAdapter } = require("./dbAdapter");
const { createStripeService } = require("./stripeService");
const { createBillingRouter, createBillingWebhookHandler } = require("./billingRoutes");
const { encrypt, hashForLookup, normalize } = require("./security/cryptoService");
const { inflateStudent } = require("./security/decryptors");

const app = express();

// ----------------- Structured Logging Helpers -----------------
const rawLog = console.log.bind(console);
const rawError = console.error.bind(console);

const logDivider = () => rawLog("============================================================");

const formatBgTime = (date = new Date()) => {
    const formatter = new Intl.DateTimeFormat("bg-BG", {
        timeZone: "Europe/Sofia",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
    return formatter.format(date);
};

const scrubRequestBody = (body) => {
    if (!body || typeof body !== "object") return body;
    const cleaned = { ...body };
    if (Object.prototype.hasOwnProperty.call(cleaned, "password")) {
        cleaned.password = "[REDACTED]";
    }
    return cleaned;
};

const logRequestStart = (req, options = {}) => {
    const { note, includeBody = true } = options;
    logDivider();
    rawLog(`[REQUEST] ${formatBgTime()} ${req.method} ${req.originalUrl}`);
    if (note) {
        rawLog(`[REQUEST] Note: ${note}`);
    }
    const query = req.query || {};
    if (Object.keys(query).length) {
        rawLog("[REQUEST] Query:", query);
    }
    if (includeBody && req.body && Object.keys(req.body).length) {
        rawLog("[REQUEST] Body:", scrubRequestBody(req.body));
    }
    logDivider();
};

console.log = (...args) => rawLog(`[INFO ${formatBgTime()}]`, ...args);
console.error = (...args) => rawError(`[ERROR ${formatBgTime()}]`, ...args);

const addStudentsToClass = async (classId, students) => {
    console.log("[CLASS STUDENTS] Begin assignment");
    console.log("[CLASS STUDENTS] classId:", classId);
    console.log("[CLASS STUDENTS] students payload:", students);

    const facultyNumbers = students
        .map(s => {
            if (typeof s === "string" || typeof s === "number") {
                return String(s);
            }
            return s?.facultyNumber || s?.faculty_number;
        })
        .filter(Boolean);

    console.log("[CLASS STUDENTS] facultyNumbers:", facultyNumbers);

    if (facultyNumbers.length === 0) {
        console.log("[CLASS STUDENTS] No valid faculty numbers provided");
        return { assignedCount: 0, facultyNumbers: [] };
    }

    const placeholders = facultyNumbers.map((_, i) => `$${i + 1}`).join(",");
    console.log("[CLASS STUDENTS] placeholders:", placeholders);

    const selectSql = `SELECT id, faculty_number FROM students WHERE faculty_number IN (${placeholders})`;
    console.log("[CLASS STUDENTS] selectSql:", selectSql);

    const result = await pool.query(selectSql, facultyNumbers);
    console.log("[CLASS STUDENTS] students matched:", result.rows);

    const idMap = {};
    result.rows.forEach(row => {
        idMap[row.id] = row.faculty_number;
    });

    const insertSql = "INSERT INTO class_students (class_id, student_id) VALUES ($1, $2) ON CONFLICT DO NOTHING";
    const studentIds = Object.keys(idMap);
    console.log("[CLASS STUDENTS] studentIds:", studentIds);

    for (const id of studentIds) {
        console.log("[CLASS STUDENTS] Assigning student_id:", id, "faculty_number:", idMap[id]);
        await pool.query(insertSql, [classId, id]);
    }

    console.log("[CLASS STUDENTS] Assignment complete");
    return { assignedCount: studentIds.length, facultyNumbers };
};

// Central CORS configuration (explicit preflight + allowed headers)
const allowedOrigins = ["https://studentcheck-9ucp.onrender.com"]; // frontend origin(s)
app.use(cors({
    origin: (origin, callback) => {
        // Allow same-origin / server-to-server (no origin header) or listed origins
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    credentials: true,
    maxAge: 86400 // cache preflight for a day
}));

// Manual lightweight preflight handler (runs after cors sets headers)
app.use((req, res, next) => {
    if (req.method === "OPTIONS") {
        // Extra headers in case cors library missed something
        res.header("Access-Control-Allow-Origin", allowedOrigins[0]);
        res.header("Access-Control-Allow-Credentials", "true");
        res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
        res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        logRequestStart(req, { note: "Preflight -> 204", includeBody: false });
        return res.status(204).end();
    }
    next();
});

// connect to PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // we'll use this later
  host: "db.imnqwnpsuapkbbnuufqn.supabase.co",
  ssl: {
    rejectUnauthorized: false, // 🔒 required for Render
  },
});

const db = createDbAdapter(pool);
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "");
const stripeService = createStripeService({
    stripe,
    db,
    appUrl: process.env.APP_URL || ""
});

// Stripe webhook must use raw body for signature verification
app.post("/api/billing/webhook", express.raw({ type: "application/json" }), createBillingWebhookHandler(stripeService));

app.use(express.json());
app.use("/api/billing", createBillingRouter(stripeService));

// Flag-controlled migration for encrypted/hash fields on sensitive columns
const APPLY_ENCRYPTION_MIGRATION = process.env.APPLY_ENCRYPTION_MIGRATION === "true";

const applyEncryptionMigration = async (client) => {
    console.log("[MIGRATION] Applying encryption/hash columns migration (if needed)...");
    await client.query(`
        ALTER TABLE students
          ADD COLUMN IF NOT EXISTS email_encrypted TEXT,
          ADD COLUMN IF NOT EXISTS email_hash TEXT,
          ADD COLUMN IF NOT EXISTS faculty_number_encrypted TEXT,
          ADD COLUMN IF NOT EXISTS faculty_number_hash TEXT;

        ALTER TABLE teachers
          ADD COLUMN IF NOT EXISTS email_encrypted TEXT,
          ADD COLUMN IF NOT EXISTS email_hash TEXT;

        CREATE INDEX IF NOT EXISTS idx_students_email_hash ON students (email_hash);
        CREATE INDEX IF NOT EXISTS idx_students_faculty_number_hash ON students (faculty_number_hash);
        CREATE INDEX IF NOT EXISTS idx_teachers_email_hash ON teachers (email_hash);
    `);
    console.log("[MIGRATION] Encryption/hash columns migration completed (or already in place).");
};





(async () => {
  try {
    const client = await pool.connect();
    console.log("✅ Connected to PostgreSQL!");
    const result = await client.query("SELECT NOW()");
    console.log("🕒 Server time:", result.rows[0]);
        // --- Ensure required tables exist (idempotent) ---
        await client.query(`
            CREATE TABLE IF NOT EXISTS classes (
                id SERIAL PRIMARY KEY,
                teacher_id INTEGER NOT NULL REFERENCES teachers(id) ON DELETE CASCADE,
                name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attendances (
                id SERIAL PRIMARY KEY,
                class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(class_id, student_id)
            );
        `);
        console.log("🛠️ Verified tables: classes, attendances");
        await db.ensureBillingTables();
        console.log("🛠️ Verified tables: org_billing, stripe_events");
        if (APPLY_ENCRYPTION_MIGRATION) {
            await applyEncryptionMigration(client);
        } else {
            console.log("[MIGRATION] APPLY_ENCRYPTION_MIGRATION=false, skipping encryption/hash migration.");
        }
    client.release();
  } catch (err) {
    console.error("❌ Database connection error:", err);
  }
})();







app.post("/teacherLogin", async (req, res) => {
    logRequestStart(req);

    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).send({ 
                error: "Email and password are required" 
            });
        }

        console.log("🔐 Checking teacher credentials for email:", email)
        
        const emailNorm = normalize(email);
        const emailHash = hashForLookup(emailNorm);

        // Query database to check if teacher exists with matching credentials
        const result = await pool.query(
            "SELECT * FROM teachers WHERE email_hash = $1 AND password = $2",
            [emailHash, password]
        );

        if (result.rows.length > 0) {
            console.log("✅ Teacher login successful");
            const teacher = result.rows[0];
            res.send({ 
                message: "Teacher login successful", 
                teacher: {
                    email: teacher.email,
                    fullName: teacher.full_name
                },
                loginSuccess: true
            });
        } else {
            console.log("❌ Invalid credentials");
            res.status(401).send({ 
                error: "Invalid email or password" 
            });
        }

    } catch (error) {
        console.error("❌ Database error during login:", error);
        res.status(500).send({ 
            error: "Internal server error" 
        });
    }
});






app.post("/studentLogin", async (req, res) => {
    logRequestStart(req);

    try {
        const { facultyNumber, password } = req.body;

        // Validate input
        if (!facultyNumber || !password) {
            return res.status(400).send({ 
                error: "Faculty number and password are required" 
            });
        }

        console.log("🔐 Checking student credentials for faculty number:", facultyNumber);

        const facultyNorm = normalize(facultyNumber);
        const facultyHash = hashForLookup(facultyNorm);

        // Query database to check if student exists with matching credentials
        const result = await pool.query(
            "SELECT * FROM students WHERE faculty_number_hash = $1 AND password = $2",
            [facultyHash, password]
        );

        if (result.rows.length > 0) {
            console.log("✅ Student login successful");
            const student = result.rows[0];
            res.send({ 
                message: "Student login successful", 
                student: student,
                loginSuccess: true
            });
        } else {
            console.log("❌ Invalid credentials");
            res.status(401).send({ 
                error: "Invalid faculty number or password" 
            });
        }

    } catch (error) {
        console.error("❌ Database error during login:", error);
        res.status(500).send({ 
            error: "Internal server error" 
        });
    }
});







app.post("/registration", async (req, res) => {
    logRequestStart(req);

    try {
        const user = req.body;
        const fullName = `${user.firstName} ${user.middleName || ''} ${user.lastName}`.replace(/\s+/g, ' ').trim();

        const courseValue = user.course;
        const groupValue = user.group;
        const validCourses = ["1", "2", "3", "4"];
        const validGroups = ["37", "38", "39", "40", "41", "42"];

        if (courseValue === undefined || courseValue === null || !validCourses.includes(String(courseValue))) {
            return res.status(400).send({ message: "Invalid course. Must be 1–4." });
        }
        if (groupValue === undefined || groupValue === null || !validGroups.includes(String(groupValue))) {
            return res.status(400).send({ message: "Invalid group. Must be 37–42." });
        }

        const normalizedEmail = normalize(user.email);
        const normalizedFacultyNumber = normalize(user.facultyNumber);

        const emailEncrypted = encrypt(normalizedEmail);
        const emailHash = hashForLookup(normalizedEmail);

        const facultyEncrypted = encrypt(normalizedFacultyNumber);
        const facultyHash = hashForLookup(normalizedFacultyNumber);

        const result = await pool.query(
            // syntax for reserved word "group" needs quotes
            `
            INSERT INTO students (
                full_name,
                email,
                faculty_number,
                password,
                level,
                faculty,
                specialization,
                "group",
                course,
                created,
                email_encrypted,
                email_hash,
                faculty_number_encrypted,
                faculty_number_hash
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
            )
            RETURNING full_name, email, faculty_number, "group", course, faculty, level, specialization
            `,
            [
                fullName,
                user.email,
                user.facultyNumber,
                user.password,
                user.level,
                user.faculty,
                user.specialization,
                String(groupValue),
                String(courseValue),
                new Date(),
                emailEncrypted,
                emailHash,
                facultyEncrypted,
                facultyHash,
            ]
        );

        const student = result.rows[0]; // inserted record without sensitive fields
        return res.send({ message: "User registration successful", student, registrationSuccess: true });
    } catch (error) {
        // Unique violation (email or other unique columns)
        if (error && error.code === '23505') {
            console.warn('⚠️ Duplicate registration attempt:', error.detail || error.constraint);
            return res.status(409).send({ 
                error: "An account with these details already exists (email or faculty number)",
                registrationSuccess: false
            });
        }
        console.error("❌ Database error during registration:", error);
        return res.status(500).send({ error: "Internal server error", registrationSuccess: false });
    }
});








app.get("/students", async (req, res) => {
    logRequestStart(req);

    const {
        level,
        faculty,
        specialization,
        group,
        search
    } = req.query || {};

    try {
        const whereClauses = [];
        const params = [];

        const addFilter = (column, value) => {
            params.push(String(value).toLowerCase());
            whereClauses.push(`LOWER(${column}) = $${params.length}`);
        };

        if (level) addFilter("level", level);
        if (faculty) addFilter("faculty", faculty);
        if (specialization) addFilter("specialization", specialization);
        if (group) addFilter("\"group\"", group);

        if (search) {
            const term = `%${String(search).toLowerCase()}%`;
            params.push(term);
            const placeholder = `$${params.length}`;
            // NOTE: search still uses legacy plaintext columns for now.
            whereClauses.push(
                `(LOWER(full_name) LIKE ${placeholder} OR LOWER(email) LIKE ${placeholder} OR LOWER(faculty_number) LIKE ${placeholder})`
            );
        }

        const whereSql = whereClauses.length ? `WHERE ${whereClauses.join(" AND ")}` : "";
        const sql = `SELECT * FROM students ${whereSql} ORDER BY id DESC`;

        const result = await pool.query(sql, params);
        const students = result.rows.map(inflateStudent);
        return res.send({ students });
    } catch (error) {
        console.error("❌ Database error fetching students:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});


// ----------------- Class Creation Endpoint -----------------
// Expects body: { name: string, teacherEmail?: string }
// Authentication placeholder: teacher identified by provided email (until token/session implemented)
app.post("/classes", async (req, res) => {
    logRequestStart(req);

    const { name, teacherEmail, students } = req.body || {};

    if (!name) {
        console.log("[CLASS CREATE] Validation failed: name is missing");
        return res.status(400).send({ error: "Class name is required" });
    }
    if (!teacherEmail) {
        console.log("[CLASS CREATE] Validation failed: teacherEmail is missing");
        return res.status(400).send({ error: "Teacher email is required for now" });
    }

    try {
        console.log("[CLASS CREATE] Step 1: Resolve teacher by email");
        console.log("[CLASS CREATE] teacherEmail:", teacherEmail);

        const teacherEmailNorm = normalize(teacherEmail);
        const teacherEmailHash = hashForLookup(teacherEmailNorm);

        const teacherResult = await pool.query(
            "SELECT id, email, full_name FROM teachers WHERE email_hash = $1",
            [teacherEmailHash]
        );

        console.log("[CLASS CREATE] teacherResult.rows.length:", teacherResult.rows.length);
        console.log("[CLASS CREATE] teacherResult.rows:", teacherResult.rows);
        if (teacherResult.rows.length === 0) {
            console.log("[CLASS CREATE] Teacher not found, aborting");
            return res.status(404).send({ error: "Teacher not found" });
        }
        const teacherId = teacherResult.rows[0].id;
        const teacherName = teacherResult.rows[0].full_name;
        console.log("[CLASS CREATE] Teacher resolved -> id:", teacherId, "name:", teacherName);

        console.log("[CLASS CREATE] Step 2: Insert class");
        console.log("[CLASS CREATE] Insert payload:", { teacher_id: teacherId, name });

        const insertResult = await pool.query(
            "INSERT INTO classes (teacher_id, name) VALUES ($1, $2) RETURNING id, teacher_id, name",
            [teacherId, name]
        );

        const created = insertResult.rows[0];

        console.log("[CLASS CREATE] Insert result rows:", insertResult.rows);
        console.log("[CLASS CREATE] Created class:", created);
        if (Array.isArray(students) && students.length > 0) {
            console.log("[CLASS CREATE] Step 3: Assigning students to class");
            const assignmentResult = await addStudentsToClass(created.id, students);
            console.log("[CLASS CREATE] Assignment result:", assignmentResult);
        } else {
            console.log("[CLASS CREATE] Step 3: No students provided, skipping assignment");
        }

        console.log("[CLASS CREATE] Step 4: Responding with created class");
        res.status(201).send({ message: "Class created", class: created });

    } catch (error) {
        console.error("❌ Database error creating class:", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// (Optional helper) List classes for a teacher by email query param: /classes?teacherEmail=...
app.get("/classes", async (req, res) => {
    logRequestStart(req);
    const { teacherEmail } = req.query;
    try {
        if (teacherEmail) {
            const teacherEmailNorm = normalize(teacherEmail);
            const teacherEmailHash = hashForLookup(teacherEmailNorm);
            const t = await pool.query("SELECT id FROM teachers WHERE email_hash = $1", [teacherEmailHash]);
            if (t.rows.length === 0) {
                return res.status(404).send({ error: "Teacher not found" });
            }
            const teacherId = t.rows[0].id;
            console.log("Fetching classes for teacher ID:", teacherId);

            const classes = await pool.query("SELECT id, teacher_id, name FROM classes WHERE teacher_id = $1 ORDER BY id DESC", [teacherId]);
            console.log("Classes fetched:", classes.rows);
            
            return res.send({ message: "Classes fetched", classes: classes.rows });
        } else {
            const classes = await pool.query("SELECT id, teacher_id, name FROM classes ORDER BY id DESC");
            return res.send({ message: "All classes fetched", classes: classes.rows });
        }
    } catch (error) {
        console.error("❌ Database error fetching classes:", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Class Rename Endpoint -----------------
// Expects body: { classId: number, name: string, teacherEmail: string }
app.put("/classes", async (req, res) => {
    logRequestStart(req);

    const { classId, name, teacherEmail } = req.body || {};

    if (!classId) {
        return res.status(400).send({ error: "classId is required" });
    }
    if (!name) {
        return res.status(400).send({ error: "name is required" });
    }
    if (!teacherEmail) {
        return res.status(400).send({ error: "teacherEmail is required" });
    }

    try {
        const teacherEmailNorm = normalize(teacherEmail);
        const teacherEmailHash = hashForLookup(teacherEmailNorm);
        const teacherResult = await pool.query(
            "SELECT id FROM teachers WHERE email_hash = $1",
            [teacherEmailHash]
        );
        if (teacherResult.rows.length === 0) {
            return res.status(404).send({ error: "Teacher not found" });
        }
        const teacherId = teacherResult.rows[0].id;

        const classResult = await pool.query(
            "SELECT id, teacher_id FROM classes WHERE id = $1",
            [classId]
        );
        if (classResult.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }
        if (classResult.rows[0].teacher_id !== teacherId) {
            return res.status(403).send({ error: "You do not have permission to rename this class" });
        }

        const updateResult = await pool.query(
            "UPDATE classes SET name = $1 WHERE id = $2 AND teacher_id = $3",
            [name, classId, teacherId]
        );

        if (updateResult.rowCount === 0) {
            return res.status(404).send({ error: "Class not found for this teacher" });
        }

        return res.status(200).send({ success: true });
    } catch (error) {
        console.error("❌ Database error renaming class:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Class Deletion Endpoint -----------------
// Expects body: { classId: number, teacherEmail: string }
// Deletes class + related rows (class_students, attendances, attendance_timestamps)
app.delete("/classes", async (req, res) => {
    logRequestStart(req);

    const { classId, teacherEmail } = req.body || {};

    if (!classId) {
        return res.status(400).send({ error: "classId is required" });
    }
    if (!teacherEmail) {
        return res.status(400).send({ error: "teacherEmail is required" });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        const teacherEmailNorm = normalize(teacherEmail);
        const teacherEmailHash = hashForLookup(teacherEmailNorm);
        const teacherResult = await client.query(
            "SELECT id FROM teachers WHERE email_hash = $1",
            [teacherEmailHash]
        );
        if (teacherResult.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).send({ error: "Teacher not found" });
        }
        const teacherId = teacherResult.rows[0].id;

        const classResult = await client.query(
            "SELECT id, teacher_id FROM classes WHERE id = $1",
            [classId]
        );
        if (classResult.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).send({ error: "Class not found" });
        }
        if (classResult.rows[0].teacher_id !== teacherId) {
            await client.query("ROLLBACK");
            return res.status(403).send({ error: "You do not have permission to delete this class" });
        }

        await client.query("DELETE FROM class_students WHERE class_id = $1", [classId]);
        await client.query("DELETE FROM attendance_timestamps WHERE class_id = $1", [classId]);
        await client.query("DELETE FROM attendances WHERE class_id = $1", [classId]);

        const deleteClass = await client.query(
            "DELETE FROM classes WHERE id = $1 AND teacher_id = $2 RETURNING id",
            [classId, teacherId]
        );

        if (deleteClass.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).send({ error: "Class not found for this teacher" });
        }

        await client.query("COMMIT");
        return res.status(200).send({ success: true });
    } catch (error) {
        await client.query("ROLLBACK");
        console.error("❌ Database error deleting class:", error);
        return res.status(500).send({ error: "Internal server error" });
    } finally {
        client.release();
    }
});



app.post("/class_students", async (req, res) => {
    logRequestStart(req);

    var classId = req.body.classId;
    var students = req.body.students; // array of student

    console.log("classId:", classId);

    try {
        if (!classId) {
            return res.status(400).send({ error: "classId is required" });
        }
        if (!Array.isArray(students) || students.length === 0) {
            return res.status(400).send({ error: "students array is required" });
        }

        const assignmentResult = await addStudentsToClass(classId, students);
        console.log("[CLASS STUDENTS] Assignment result:", assignmentResult);

        res.send({ message: "Students added to class successfully" });
    } catch (error) {
        console.error("Error adding students to class:", error);
        res.status(500).send({ message: "Error on adding students to class (database error)" });
    }
    

    
});






app.get("/class_students", async (req, res) => {
    logRequestStart(req);
    var classId = req.query.class_id;
    console.log("classId:", classId);
    if (!classId) {
        return res.status(400).send({ error: "class_id query parameter is required" });
    }
    var result  = await pool.query("SELECT * FROM class_students WHERE class_id = $1", [classId]);
    console.log('Query result:', result.rows);

    // get student details for each student_id
    var studentIds = [];
    result.rows.forEach(row => {
        var studentId = row.student_id;
        console.log("Student ID in class:", studentId);
        studentIds.push(studentId);
    });

    console.log("Student IDs in class:", studentIds);

    // Fetch details for these students
    let studentsDetails = [];
    if (studentIds.length > 0) {
        const placeholders = studentIds.map((_, i) => `$${i + 1}`).join(',');
        const sql = `SELECT id, full_name, faculty_number FROM students WHERE id IN (${placeholders})`;
        const detailsRes = await pool.query(sql, studentIds);
        studentsDetails = detailsRes.rows;
    }

    console.log("Students details fetched:", studentsDetails);

    return res.send({
        message: "Class students fetched",
        students: studentsDetails // add names and faculty numbers by id
    });
});





app.get("/get_student_classes", async (req, res) => {
    logRequestStart(req);

    const rawStudentId = req.query.student_id;
    console.log("studentId (raw):", rawStudentId);

    if (!rawStudentId || rawStudentId === "undefined" || rawStudentId === "null") {
        return res.status(400).send({ error: "student_id query parameter is required" });
    }

    const studentId = Number(rawStudentId);
    if (!Number.isFinite(studentId) || studentId <= 0) {
        return res.status(400).send({ error: "student_id must be a valid number" });
    }

    const sql = `SELECT * FROM class_students WHERE student_id = $1`;
    const result  = await pool.query(sql, [studentId]);

    console.log('Query result:', result.rows);




    // Collect unique class IDs from result rows
    const classIds = Array.from(new Set(result.rows.map(row => Number(row.class_id)).filter(Boolean)));

    let classNames = [];

    if (classIds.length > 0) {
        const placeholders = classIds.map((_, i) => `$${i + 1}`).join(',');
        const sql = `SELECT id, name FROM classes WHERE id IN (${placeholders})`;
        const { rows: classRows } = await pool.query(sql, classIds);

        // Build id -> name map
        const nameById = new Map(classRows.map(row => [Number(row.id), row.name]));

        // Preserve original order if needed
        classNames = result.rows
            .map(row => nameById.get(Number(row.class_id)))
            .filter(Boolean);
    }





    console.log("Class names:", classNames);

    return res.send({
        message: "Student classes fetched",
        class_names: classNames
    });

});





app.get("/get_class_id_by_name", async (req, res) => {
    logRequestStart(req);

    var className = req.query.class_name;
    console.log("className:", className);

    const sql = `SELECT id FROM classes WHERE name = $1`;
    const result  = await pool.query(sql, [className]);

    console.log('Query result:', result.rows);

    if (result.rows.length === 0) {
        return res.status(404).send({ error: "Class not found" });
    }

    const class_id = result.rows[0].id;

    console.log("Class ID:", class_id);

    return res.send({
        message: "Class ID fetched",
        class_id: class_id
    });
});



// ----------------- Attendance Recording Endpoint -----------------
// Accepts body: { class_id, student_ids } or { class_id, student_id } or { class_id, faculty_number }
app.post("/attendance", async (req, res) => {
    logRequestStart(req);
    
    const { class_id, student_ids, student_id, faculty_number } = req.body || {};

    console.log("[ATTENDANCE] Body:", req.body);
    console.log("[ATTENDANCE] class_id:", class_id);
    console.log("[ATTENDANCE] student_ids:", student_ids);
    console.log("[ATTENDANCE] student_id:", student_id);
    console.log("[ATTENDANCE] faculty_number:", faculty_number);

    if (!class_id || (!student_ids && !student_id && !faculty_number)) {
        console.log("[ATTENDANCE] Validation failed: missing required fields");
        return res.status(400).send({ error: "class_id and student_id or faculty_number are required" });
    }

    try {
        const classIdNum = Number(class_id);
        if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
            return res.status(400).send({ error: "class_id must be a valid number" });
        }

        // Verify class exists
        console.log("[ATTENDANCE] Checking class existence");
        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        console.log("[ATTENDANCE] classCheck.rows:", classCheck.rows);
        if (classCheck.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        const upsertSql = `
            INSERT INTO attendances (class_id, student_id)
            VALUES ($1, $2)
            ON CONFLICT (class_id, student_id)
            DO UPDATE SET count = COALESCE(attendances.count, 0) + 1
            RETURNING id, class_id, student_id, count
        `;

        // Branch 1: array of student IDs
        if (Array.isArray(student_ids)) {
            console.log("[ATTENDANCE] Branch: student_ids array");
            const studentIdsInt = student_ids
                .map(value => Number(value))
                .filter(Number.isFinite);

            const uniqueIds = Array.from(new Set(studentIdsInt));

            if (uniqueIds.length === 0) {
                return res.status(400).send({ error: "No valid student_ids provided" });
            }

            const results = [];
            console.log("[ATTENDANCE] Processing attendance for IDs:", uniqueIds);
            for (const sid of uniqueIds) {
                console.log(`[ATTENDANCE] Recording attendance class_id=${classIdNum}, student_id=${sid}`);
                const { rows } = await pool.query(upsertSql, [classIdNum, sid]);
                results.push(rows[0]);
            }

            console.log("[ATTENDANCE] Results:", results);
            return res.status(200).send({ success: true, attendance: results });
        }

        // Branch 2: single student_id or faculty_number
        console.log("[ATTENDANCE] Branch: single student");
        let resolvedStudentId = null;

        if (student_id !== undefined && student_id !== null) {
            const sid = Number(student_id);
            if (!Number.isFinite(sid) || sid <= 0) {
                return res.status(400).send({ error: "student_id must be a valid number" });
            }
            console.log("[ATTENDANCE] Looking up student by id:", sid);
            const studentCheck = await pool.query("SELECT id FROM students WHERE id = $1", [sid]);
            console.log("[ATTENDANCE] studentCheck.rows:", studentCheck.rows);
            if (studentCheck.rows.length === 0) {
                return res.status(404).send({ error: "Student not found" });
            }
            resolvedStudentId = sid;
            console.log("[ATTENDANCE] Resolved student_id:", resolvedStudentId);
        } else if (faculty_number) {
            console.log("[ATTENDANCE] Looking up student by faculty_number:", faculty_number);
            const facNorm = normalize(faculty_number);
            const facHash = hashForLookup(facNorm);
            const studentCheck = await pool.query(
                "SELECT id FROM students WHERE faculty_number_hash = $1",
                [facHash]
            );
            console.log("[ATTENDANCE] studentCheck.rows:", studentCheck.rows);
            if (studentCheck.rows.length === 0) {
                return res.status(404).send({ error: "Student not found" });
            }
            resolvedStudentId = studentCheck.rows[0].id;
            console.log("[ATTENDANCE] Resolved student_id from faculty_number:", resolvedStudentId);
        }

        if (!resolvedStudentId) {
            return res.status(400).send({ error: "student_id or faculty_number is required" });
        }

        console.log("[ATTENDANCE] Upserting attendance with:", { classIdNum, resolvedStudentId });
        const { rows } = await pool.query(upsertSql, [classIdNum, resolvedStudentId]);
        console.log("[ATTENDANCE] Result:", rows[0]);
        return res.status(200).send({ success: true, attendance: rows[0] });
    } catch (error) {
        console.error("❌ Database error recording attendance:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// List attendance entries optionally filtered by classId: /attendance?classId=...
app.get("/attendance", async (req, res) => {
    logRequestStart(req);
    
    const classId = req.query.class_id;
    const studentId = req.query.student_id;

    try {
        if (classId) {

            const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classId]);
            if (classCheck.rows.length === 0) {
                return res.status(404).send({ error: "Class not found" });
            }

            const rows = await pool.query(`
                SELECT a.id, a.class_id, a.student_id, a.count, s.full_name AS student_name
                FROM attendances a
                JOIN students s ON a.student_id = s.id
                WHERE a.class_id = $1
                ORDER BY a.timestamp DESC
            `, [classId]);
            return res.send({ message: "Attendance fetched", attendance: rows.rows });
        }


        const rows = await pool.query(`
            SELECT a.id, a.class_id, a.student_id, a.timestamp,
                         s.full_name AS student_name, c.name AS class_name
            FROM attendances a
            JOIN students s ON a.student_id = s.id
            JOIN classes c ON a.class_id = c.id
            ORDER BY a.timestamp DESC
        `);
        return res.send({ message: "All attendance fetched", attendance: rows.rows });
    } catch (error) {
        console.error("❌ Database error fetching attendance:", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Attendance Timestamps Endpoint -----------------
// Query: /attendance/timestamps?class_id=...
app.get("/attendance/timestamps", async (req, res) => {
    logRequestStart(req);

    const classId = req.query.class_id;
    console.log("[ATTENDANCE TIMESTAMPS] class_id:", classId);

    if (!classId) {
        return res.status(400).send({ error: "class_id query parameter is required" });
    }

    const classIdNum = Number(classId);
    if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
        return res.status(400).send({ error: "class_id must be a valid number" });
    }

    try {
        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        if (classCheck.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        const rows = await pool.query(`
            SELECT 
                at.class_id,
                at.student_id,
                s.full_name,
                s.faculty_number,
                at.joined_at,
                at.left_at
            FROM attendance_timestamps at
            JOIN students s ON at.student_id = s.id
            WHERE at.class_id = $1
            ORDER BY at.joined_at DESC
        `, [classIdNum]);

        return res.send({ timestamps: rows.rows });
    } catch (error) {
        console.error("❌ Database error fetching attendance timestamps:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Attendance History Endpoint -----------------
// Query: /attendance/history?class_id=...&student_id=...&faculty_number=...
app.get("/attendance/history", async (req, res) => {
    logRequestStart(req);

    const { class_id, student_id, faculty_number } = req.query || {};
    console.log("[ATTENDANCE HISTORY] class_id:", class_id);
    console.log("[ATTENDANCE HISTORY] student_id:", student_id);
    console.log("[ATTENDANCE HISTORY] faculty_number:", faculty_number);

    if (!class_id) {
        return res.status(400).send({ error: "class_id is required" });
    }

    const classIdNum = Number(class_id);
    if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
        return res.status(400).send({ error: "class_id must be a valid number" });
    }

    try {
        let resolvedStudentId = null;

        if (student_id !== undefined && student_id !== null && String(student_id).length > 0) {
            const sid = Number(student_id);
            if (!Number.isFinite(sid) || sid <= 0) {
                return res.status(400).send({ error: "student_id must be a valid number" });
            }
            resolvedStudentId = sid;
            console.log("[ATTENDANCE HISTORY] Using student_id:", resolvedStudentId);
        } else if (faculty_number) {
            console.log("[ATTENDANCE HISTORY] Resolving student by faculty_number:", faculty_number);
            const facNorm = normalize(faculty_number);
            const facHash = hashForLookup(facNorm);
            const studentCheck = await pool.query(
                "SELECT id FROM students WHERE faculty_number_hash = $1",
                [facHash]
            );
            if (studentCheck.rows.length === 0) {
                return res.status(404).send({ error: "Student not found" });
            }
            resolvedStudentId = studentCheck.rows[0].id;
            console.log("[ATTENDANCE HISTORY] Resolved student_id:", resolvedStudentId);
        } else {
            return res.status(400).send({ error: "student_id or faculty_number is required" });
        }

        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        if (classCheck.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        const { rows } = await pool.query(
            `
            SELECT joined_at, left_at
            FROM attendance_timestamps
            WHERE class_id = $1 AND student_id = $2
            ORDER BY joined_at DESC
            `,
            [classIdNum, resolvedStudentId]
        );

        return res.status(200).send({ records: rows });
    } catch (error) {
        console.error("❌ Database error fetching attendance history:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Attendance Summary Endpoint -----------------
// Query: /attendance/summary?class_id=...
app.get("/attendance/summary", async (req, res) => {
    logRequestStart(req);

    const classId = req.query.class_id;
    console.log("[ATTENDANCE SUMMARY] class_id:", classId);

    if (!classId) {
        return res.status(400).send({ error: "class_id is required" });
    }

    const classIdNum = Number(classId);
    if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
        return res.status(400).send({ error: "class_id must be a valid number" });
    }

    try {
        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        if (classCheck.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        const { rows } = await pool.query(
            `
            SELECT 
                a.student_id,
                s.full_name,
                s.faculty_number,
                COALESCE(a.count, 0) AS attendance_count
            FROM attendances a
            JOIN students s ON a.student_id = s.id
            WHERE a.class_id = $1
            ORDER BY s.full_name ASC
            `,
            [classIdNum]
        );

        return res.status(200).send({ items: rows });
    } catch (error) {
        console.error("❌ Database error fetching attendance summary:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});



// ----------------- Remove Student from Class Endpoint -----------------
// Expects body: { class_id: number, faculty_number: string, teacherEmail: string }
// Validates that teacher owns the class before deleting
app.post("/class_students/remove", async (req, res) => {
    logRequestStart(req);

    const classId = req.body.class_id ?? req.body.classId;
    const facultyNumberRaw = req.body.faculty_number ?? req.body.facultyNumber;
    const teacherEmail = req.body.teacherEmail;
    const facultyNumber = facultyNumberRaw ? String(facultyNumberRaw).trim() : facultyNumberRaw;

    // Validate required fields
    if (!classId || !facultyNumber) {
        return res.status(400).send({ error: "class_id and faculty_number are required" });
    }
    if (!teacherEmail) {
        return res.status(400).send({ error: "teacherEmail is required for authorization" });
    }

    try {
        // Step 0: Get student ID from faculty number (hashed lookup)
        const facultyNorm = normalize(facultyNumber);
        const facultyHash = hashForLookup(facultyNorm);
        const studentResult = await pool.query(
            "SELECT id FROM students WHERE faculty_number_hash = $1",
            [facultyHash]
        );
        if (studentResult.rows.length === 0) {
            return res.status(404).send({ error: "Student not found with this faculty number" });
        }
        const student_id = studentResult.rows[0].id;
        console.log("Student ID found:", student_id);

        // Step 1: Verify teacher exists and get teacher ID
        const teacherResult = await pool.query(
            "SELECT id FROM teachers WHERE email = $1",
            [teacherEmail]
        );
        if (teacherResult.rows.length === 0) {
            return res.status(401).send({ error: "Teacher not found" });
        }
        const teacherId = teacherResult.rows[0].id;
        console.log("Teacher ID found:", teacherId);

        // Step 2: Verify teacher owns the class
        const classResult = await pool.query(
            "SELECT id, teacher_id FROM classes WHERE id = $1",
            [classId]
        );
        if (classResult.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }
        const classTeacherId = classResult.rows[0].teacher_id;
        if (classTeacherId !== teacherId) {
            return res.status(403).send({ error: "You do not have permission to modify this class" });
        }
        console.log("Teacher ownership verified for class:", class_id);

        // Step 3: Verify student exists in class_students
        const studentInClassResult = await pool.query(
            "SELECT id FROM class_students WHERE class_id = $1 AND student_id = $2",
            [classId, student_id]
        );
        if (studentInClassResult.rows.length === 0) {
            return res.status(404).send({ error: "Student not found in this class" });
        }
        console.log("Student found in class");

        // Step 4: Delete the record from class_students
        const deleteResult = await pool.query(
            "DELETE FROM class_students WHERE class_id = $1 AND student_id = $2 RETURNING id",
            [classId, student_id]
        );
        console.log("Student removed from class:", deleteResult.rows[0]);

        res.status(200).send({ 
            message: "Student successfully removed from class",
            deletedRecord: deleteResult.rows[0]
        });

    } catch (error) {
        console.error("❌ Database error removing student from class:", error);
        res.status(500).send({ error: "Internal server error" });
    }
});




// Lightweight heartbeat endpoint: fast 204, no caching, accepts any method
app.all("/heartbeat", (req, res) => {
    logRequestStart(req, { includeBody: false });
    // Set no-cache headers
    res.set({
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "Surrogate-Control": "no-store"
    });
    // No body needed; 204 keeps it minimal and fast
    res.status(204).end();
});





app.post("/save_student_timestamps", async (req, res) => {
    logRequestStart(req);
    
    var classId = req.body.class_id;
    var studentFacultyNumber = req.body.faculty_number;

    const facNorm = normalize(studentFacultyNumber);
    const facHash = hashForLookup(facNorm);

    const studentIdQueryResult = await pool.query(
        "SELECT id FROM students WHERE faculty_number_hash = $1",
        [facHash]
    );

    const studentId = Number(studentIdQueryResult.rows[0].id);

    if(!studentId){
        console.error("Error: Student not found with faculty number:", studentFacultyNumber);
        return res.status(404).send({ error: "Student not found in database." });
    }

    var joined_at_raw = req.body.joined_at;
    var left_at_raw = req.body.left_at;

    if(joined_at_raw == null || left_at_raw == null){
        console.error("This student has not attended the class: ", studentFacultyNumber);
        return res.status(400).send({ error: `${studentFacultyNumber} has not been marked as attended.` });
    }

    // Format timestamps in Bulgarian timezone (Europe/Sofia)
    const dateTimeBG = new Intl.DateTimeFormat('bg-BG', {
        timeZone: 'Europe/Sofia',
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
    });

    const joinedAtDate = new Date(joined_at_raw);
    const leftAtDate = new Date(left_at_raw);

    var joined_at = dateTimeBG.format(joinedAtDate);
    var left_at = dateTimeBG.format(leftAtDate);
    
    console.log("joined_at timestamp:", joined_at);
    console.log("left_at timestamp:", left_at);

    const sql = `INSERT INTO attendance_timestamps (class_id, student_id, joined_at, left_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`;

    const result  = await pool.query(sql, [classId, studentId, joined_at, left_at]);

    console.log("Student timestamps saved successfully for student:", studentId);
    
    return res.send({
        message: "Student timestamps saved"
    });

});



app.get("/get_student_attendance_count", async (req, res) => {
    logRequestStart(req);

    var classId = req.query.class_id;
    var studentId = req.query.student_id;
    var facultyNumber = req.query.faculty_number;

    console.log("classId:", classId, "studentId:", studentId, "facultyNumber:", facultyNumber);

    if (!classId || (!studentId && !facultyNumber)) {
        return res.status(400).send({ error: "class_id and student_id or faculty_number are required" });
    }

    const classIdNum = Number(classId);
    if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
        return res.status(400).send({ error: "class_id must be a valid number" });
    }

    let studentIdNum = null;
    const resolveFacultyNumber = facultyNumber || studentId;

    if (resolveFacultyNumber) {
        console.log("[ATTENDANCE COUNT] Resolving student by faculty_number:", resolveFacultyNumber);
        const facNorm = normalize(resolveFacultyNumber);
        const facHash = hashForLookup(facNorm);
        const studentLookup = await pool.query(
            "SELECT id FROM students WHERE faculty_number_hash = $1",
            [facHash]
        );
        console.log("[ATTENDANCE COUNT] studentLookup.rows:", studentLookup.rows);
        if (studentLookup.rows.length === 0) {
            return res.status(404).send({ error: "Student not found" });
        }
        studentIdNum = studentLookup.rows[0].id;
    } else {
        return res.status(400).send({ error: "student_id or faculty_number is required" });
    }
    console.log("[ATTENDANCE COUNT] Using studentId:", studentIdNum);

    const sqlForStudentAttendance = `
        SELECT COALESCE((SELECT count FROM attendances WHERE class_id = $1 AND student_id = $2), 0) AS count
    `;

    const sqlForTotalCompletedClasses = `
        SELECT COALESCE(completed_classes_count, 0) AS completed_classes_count FROM classes WHERE id = $1
    `;

    const result  = await pool.query(sqlForStudentAttendance, [classIdNum, studentIdNum]);
    const result2 = await pool.query(sqlForTotalCompletedClasses, [classIdNum]);

    console.log('Query result:', result.rows);
    console.log('Query result 2:', result2.rows);

    const attendanceCount = Number(result.rows[0]?.count ?? 0);
    const totalCompletedClassesCount = Number(result2.rows[0]?.completed_classes_count ?? 0);
    

    console.log("Attendance count:", attendanceCount);
    console.log("Total completed classes count:", totalCompletedClassesCount);
    
    return res.send({
        message: "Student attendance count fetched",
        attendance_count: attendanceCount,
        total_completed_classes_count: totalCompletedClassesCount
    });

});



app.post("/update_completed_classes_count", async (req, res) => {
    logRequestStart(req);
    
    var classId = req.body.class_id;

    console.log("classId:", classId);

    const sql = `UPDATE classes SET completed_classes_count = completed_classes_count + 1 WHERE id = $1`;
    const result  = await pool.query(sql, [classId]);

    console.log('Query result:', result.rows);
    
    return res.send({
        message: "Completed classes count updated"
    });

});





app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
