const PORT = process.env.PORT || 3000;
const DATABASE_URL = "postgresql://postgres:***REMOVED***@DB_HOST:5432/postgres";

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg"); // PostgreSQL client
const { createEmailVerificationRouter, ensureSchema } = require("./emailVerification");

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
    client.release();

        await ensureSchema(pool);
        console.log("🗂️ Email verification schema ensured");
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




app.use("/auth", createEmailVerificationRouter(pool, {
    cooldownSeconds: 60,
    codeTTLMinutes: 10,
    maxVerifyAttempts: 5,
    maxResends: 3
}));


app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
