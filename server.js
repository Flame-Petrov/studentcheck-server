const PORT = process.env.PORT || 3000;
const DATABASE_URL = "postgresql://postgres:***REMOVED***@DB_HOST:5432/postgres";

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg"); // PostgreSQL client

const app = express();

// cors should be the thing used by "app"
app.use(cors({
  origin: "https://studentcheck-9ucp.onrender.com", // ✅ your frontend Render URL
  methods: ["GET", "POST"],
  credentials: true
}));
app.options("*", cors()); // enable pre-flight for all routes
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
    console.log('Request body:', req.body);
    const user = req.body;
    const fullName = `${user.firstName} ${user.middleName} ${user.lastName}`;
    const result = await pool.query(
      "INSERT INTO students (full_name, email, faculty_number, password, created) VALUES ($1, $2, $3, $4, $5)",
      [fullName, user.email, user.facultyNumber, user.password, new Date()]
    );
    const student = result.rows[0]; // <- the inserted record
    res.send({ message: "User registration successful", student: student, registrationSuccess: true });
});

app.post("/students", async (req, res) => {

    res.send({message: "Students endpoint reached" });
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
