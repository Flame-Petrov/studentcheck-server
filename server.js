const PORT = process.env.PORT || 3000;
const DATABASE_URL = "postgresql://postgres:***REMOVED***@DB_HOST:5432/postgres";

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg"); // PostgreSQL client

const app = express();

// Central CORS configuration (explicit preflight + allowed headers)
const allowedOrigins = ["https://studentcheck-9ucp.onrender.com"]; // frontend origin(s)
app.use(cors({
    origin: (origin, callback) => {
        // Allow same-origin / server-to-server (no origin header) or listed origins
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "OPTIONS"],
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
        res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        console.log(`🛰️ Preflight ${req.method} ${req.originalUrl} -> 204`);
        return res.status(204).end();
    }
    next();
});

app.use(express.json());

// connect to PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // we'll use this later
  host: "DB_HOST",
  ssl: {
    rejectUnauthorized: false, // 🔒 required for Render
  },
});





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
    client.release();
  } catch (err) {
    console.error("❌ Database connection error:", err);
  }
})();







app.post("/teacherLogin", async (req, res) => {

    console.log();
    console.log('Received POST /teacherLogin');
    console.log('Request body:', req.body);

    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).send({ 
                error: "Email and password are required" 
            });
        }

        console.log("🔐 Checking teacher credentials for email:", email)
        
        // Query database to check if teacher exists with matching credentials
        const result = await pool.query(
            "SELECT * FROM teachers WHERE email = $1 AND password = $2",
            [email, password]
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

    console.log();
    console.log('Received POST /studentLogin');
    console.log('Request body:', req.body);

    try {
        const { facultyNumber, password } = req.body;

        // Validate input
        if (!facultyNumber || !password) {
            return res.status(400).send({ 
                error: "Faculty number and password are required" 
            });
        }

        console.log("🔐 Checking student credentials for faculty number:", facultyNumber);

        // Query database to check if student exists with matching credentials
        const result = await pool.query(
            "SELECT * FROM students WHERE faculty_number = $1 AND password = $2",
            [facultyNumber, password]
        );

        if (result.rows.length > 0) {
            console.log("✅ Student login successful");
            const student = result.rows[0];
            res.send({ 
                message: "Student login successful", 
                student: {
                    facultyNumber: student.faculty_number,
                    fullName: student.full_name,
                    email: student.email
                },
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

    console.log();
    console.log('Received POST /registration');
    // Avoid logging passwords in plaintext
    const { password: _pw, ...safeBody } = req.body || {};
    console.log('Request body (sanitized):', safeBody);

    try {
        const user = req.body;
        const fullName = `${user.firstName} ${user.middleName || ''} ${user.lastName}`.replace(/\s+/g, ' ').trim();

                const result = await pool.query(
                    // syntax for reserved word "group" needs quotes
                    "INSERT INTO students (full_name, email, faculty_number, password, created, \"group\") VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, full_name, email, faculty_number, created, \"group\"",
                    [fullName, user.email, user.facultyNumber, user.password, new Date(), user.group]
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
    console.log();
    console.log('Received GET /students');
    var result = await pool.query("SELECT * FROM students");
    // console.log('Query result:', result.rows);
    result = result.rows;
    // console.log('Processed result:', result);
    res.send({message: "Students endpoint reached", students: result });
});


// ----------------- Class Creation Endpoint -----------------
// Expects body: { name: string, teacherEmail?: string }
// Authentication placeholder: teacher identified by provided email (until token/session implemented)
app.post("/classes", async (req, res) => {
    console.log();
    console.log("Received POST /classes");
    console.log("Request body:", req.body);

    const { name, teacherEmail } = req.body || {};

    if (!name) {
        console.log("Class name is missing in request");
        return res.status(400).send({ error: "Class name is required" });
    }
    if (!teacherEmail) {
        console.log("Teacher email is missing in request");
        return res.status(400).send({ error: "Teacher email is required for now" });
    }

    try {
        const teacherResult = await pool.query("SELECT id, email, full_name FROM teachers WHERE email = $1", [teacherEmail]);
        if (teacherResult.rows.length === 0) {
            return res.status(404).send({ error: "Teacher not found" });
        }
        const teacherId = teacherResult.rows[0].id;
        console.log("Teacher ID found:", teacherId);    

        const insertResult = await pool.query(
            "INSERT INTO classes (teacher_id, name) VALUES ($1, $2) RETURNING id, teacher_id, name",
            [teacherId, name]
        );

        const created = insertResult.rows[0];

        console.log("Class inserted:", created);
        res.status(201).send({ message: "Class created", class: created });

    } catch (error) {
        console.error("❌ Database error creating class:", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// (Optional helper) List classes for a teacher by email query param: /classes?teacherEmail=...
app.get("/classes", async (req, res) => {
    console.log();
    console.log("Received GET /classes");
    console.log("Query params:", req.query);
    const { teacherEmail } = req.query;
    try {
        if (teacherEmail) {
            const t = await pool.query("SELECT id FROM teachers WHERE email = $1", [teacherEmail]);
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



app.post("/class_students", async (req, res) => {

    console.log();
    console.log('Received POST /class_students');
    console.log('Request body:', req.body);

    var classId = req.body.classId;
    var students = req.body.students; // array of student
    
    var studentIds = [];

    console.log("classId:", classId);

    console.log("Extracting student IDs using faculty numbers from Database...");
    students.forEach(async student => {
        const studentId = await pool.query("SELECT id FROM students WHERE faculty_number = $1", [student.facultyNumber]);
        studentIds.push(studentId.rows[0].id);
    });

    console.log("studentIds:", studentIds);

});






app.get("/class_students", async (req, res) => {
    console.log();
    console.log('Received GET /class_students');
    console.log("Query params:", req.query);
    var classId = req.query.class_id;
    console.log("classId:", classId);
    if (!classId) {
        return res.status(400).send({ error: "class_id query parameter is required" });
    }
    var result  = await pool.query("SELECT * FROM class_students WHERE class_id = $1", [classId]);
    console.log('Query result:', result.rows);
    return res.send({message: "Class students fetched", students: result.rows });
});









// ----------------- Attendance Recording Endpoint -----------------
// Expects body: { classId: number, studentId: number }
app.post("/attendance", async (req, res) => {
    console.log();
    console.log("Received POST /attendance");
    const { classId, studentId } = req.body || {};

    if (!classId || !studentId) {
        return res.status(400).send({ error: "classId and studentId are required" });
    }

    try {
        // Validate class
        const classResult = await pool.query("SELECT id FROM classes WHERE id = $1", [classId]);
        if (classResult.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        // Validate student
        const studentResult = await pool.query("SELECT id FROM students WHERE id = $1", [studentId]);
        if (studentResult.rows.length === 0) {
            return res.status(404).send({ error: "Student not found" });
        }

        // Prevent duplicate
        const duplicateCheck = await pool.query(
            "SELECT id FROM attendances WHERE class_id = $1 AND student_id = $2",
            [classId, studentId]
        );
        if (duplicateCheck.rows.length > 0) {
            return res.status(409).send({ error: "Attendance already recorded", attendanceId: duplicateCheck.rows[0].id });
        }

        const insertAttendance = await pool.query(
            "INSERT INTO attendances (class_id, student_id) VALUES ($1, $2) RETURNING id, class_id, student_id, timestamp",
            [classId, studentId]
        );

        res.status(201).send({ message: "Attendance recorded", attendance: insertAttendance.rows[0] });
    } catch (error) {
        console.error("❌ Database error recording attendance:", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// List attendance entries optionally filtered by classId: /attendance?classId=...
app.get("/attendance", async (req, res) => {
    console.log();
    console.log("Received GET /attendance");
    const { classId } = req.query;
    try {
        if (classId) {
            const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classId]);
            if (classCheck.rows.length === 0) {
                return res.status(404).send({ error: "Class not found" });
            }
            const rows = await pool.query(`
                SELECT a.id, a.class_id, a.student_id, a.timestamp,
                             s.full_name AS student_name
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





// Lightweight heartbeat endpoint: fast 204, no caching, accepts any method
app.all("/heartbeat", (req, res) => {
    console.log();
    console.log(`Received ${req.method} /heartbeat`);
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






app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
