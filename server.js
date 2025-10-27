const PORT = process.env.PORT || 3000;
const DATABASE_URL = "postgresql://USER:***REMOVED***@HOST/DATABASE";


const express = require("express");
const cors = require("cors");
const { Pool } = require("pg"); // PostgreSQL client

const app = express();
app.use(express.json());
app.use(cors({
  origin: "https://studentcheck-9ucp.onrender.com", // ✅ your frontend Render URL
  methods: ["GET", "POST"],
  credentials: true
}));


// connect to PostgreSQL
const pool = new Pool({
  connectionString: DATABASE_URL, // we'll use this later
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

app.post("/studentLogin", async (req, res) => {

    console.log();
    console.log('Received POST /studentLogin');
    console.log('Request body:', req.body);

    console.log("🔐 Student Logged In");
    const { username, password } = req.body;
    // await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [username, password]);
    res.send({ message: "Student login successful" });
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
