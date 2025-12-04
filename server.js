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

    console.log("classId:", classId);

    console.log("Extracting student IDs using faculty numbers from Database...");
    try{
        var facultyNumbers = students.map(s => s.facultyNumber || s.faculty_number).filter(Boolean);
        console.log("facultyNumbers:", facultyNumbers);

        var placeholders = facultyNumbers.map((_, i) => `$${i + 1}`).join(',');
        console.log("placeholders:", placeholders);

        var sql = `SELECT id, faculty_number FROM students WHERE faculty_number IN (${placeholders})`;
        console.log("SQL:", sql);

        var result = await pool.query(sql, facultyNumbers);

        var idMap = {};
        result.rows.forEach(row => {
            idMap[row.id] = row.faculty_number;
        });
        
        var sqlInsert = "INSERT INTO class_students (class_id, student_id) VALUES ($1, $2) ON CONFLICT DO NOTHING";
        Object.keys(idMap).forEach(id => {
            console.log("Student ID:", id, "Faculty Number:", idMap[id]);
            pool.query(sqlInsert, [classId, id]);
        });

        console.log("Students successfully added to class.");

        res.send({ message: "Students added to class successfully" });

    }catch(error){
        var errorMessage;
        if(error.type === 'TypeError'){
            errorMessage = "No students provided to be added to the database.";
            console.error(errorMessage);
        }else{
            console.error("Error extracting student IDs:", error);
        }

        res.send({ message: "Error on adding students to class (database error)" });
    }
    

    
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

    console.log();
    console.log('Received GET /get_student_classes');
    console.log("Query params:", req.query);

    var studentId = req.query.student_id;;
    console.log("studentId:", studentId);

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
    console.log();
    console.log('Received GET /get_class_id_by_name');
    console.log("Query params:", req.query);

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
// Expects body: { classId: number, studentId: number }
app.post("/attendance", async (req, res) => {
    console.log();
    console.log("Received POST /attendance");
    console.log("Request body:", req.body);
    
    const classId = req.body.class_id;
    const studentIds = req.body.student_ids; // expect array of student IDs

    console.log("classId:", classId);
    console.log("studentIds:", studentIds);

    if (!classId || !studentIds) {
        return res.status(400).send({ error: "classId and studentIds are required" });
    }

    try {

        const classIdNum = Number(classId);
        const studentIdsInt = studentIds
            .map(value => Number(value))
            .filter(Number.isFinite);

        const uniqueIds = Array.from(new Set(studentIdsInt));

        if (studentIdsInt.length === 0) {
            return res.status(400).send({ error: "No valid studentIds provided" });
        }

        const upsertSql = `
            INSERT INTO attendances (class_id, student_id)
            VALUES ($1, $2)
            ON CONFLICT (class_id, student_id)
            DO UPDATE SET count = COALESCE(attendances.count, 0) + 1
            RETURNING id, class_id, student_id, count
        `;

        const results = [];

        console.log("Processing attendance for student IDs:", studentIds);
        
        for (const studentId of uniqueIds) {
            console.log(`Recording attendance for classId: ${classId}, studentId: ${studentId}`);
            const { rows } = await pool.query(upsertSql, [classIdNum, studentId]);
            results.push(rows[0]);
        }

        console.log("Attendance results:", results);

        res.status(201).send({ message: "Attendance processed", attendance: results });
    } catch (error) {
        console.error("❌ Database error recording attendance:", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// List attendance entries optionally filtered by classId: /attendance?classId=...
app.get("/attendance", async (req, res) => {
    console.log();
    console.log("Received GET /attendance");
    console.log("Query params:", req.query);
    
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






app.get("/get_student_attendance_count", async (req, res) => {
    
    console.log();
    console.log('Received GET /student_attendance_count');
    console.log("Query params:", req.query);

    var classId = req.query.class_id;
    var studentId = req.query.student_id;;

    console.log("classId:", classId, "studentId:", studentId);

    const sqlForStudentAttendance = `SELECT count FROM attendances WHERE class_id = $1 AND student_id = $2`;

    const sqlForTotalCompletedClasses = `SELECT completed_classes_count FROM classes WHERE id = $1`;

    const result  = await pool.query(sqlForStudentAttendance, [classId, studentId]);
    const result2 = await pool.query(sqlForTotalCompletedClasses, [classId]);

    console.log('Query result:', result.rows);
    console.log('Query result 2:', result2.rows);

    let attendanceCount = 0;
    let totalCompletedClassesCount = 0;

    try{
        attendanceCount = result.rows[0].count;
    }catch(error){
        console.log("Error extracting attendanceCount or totalCompletedClassesCount:", error);
    }

    try{
        totalCompletedClassesCount = result2.rows[0].completed_classes_count;
    }catch(error){
        console.log("Error extracting totalCompletedClassesCount:", error);
    }
    

    console.log("Attendance count:", attendanceCount);
    console.log("Total completed classes count:", totalCompletedClassesCount);
    
    return res.send({
        message: "Student attendance count fetched",
        attendance_count: attendanceCount,
        total_completed_classes_count: totalCompletedClassesCount
    });

});



app.post("/update_completed_classes_count", async (req, res) => {

    console.log();
    console.log('Received POST /update_completed_classes_count');
    console.log('Request body:', req.body);
    
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
