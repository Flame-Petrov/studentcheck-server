const express = require("express");
const { Pool } = require("pg"); // PostgreSQL client

const app = express();
app.use(express.json());

// connect to PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // we'll use this later
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, password]);
  res.send("User registered!");
});

app.listen(3000, () => console.log("✅ Server running on port 3000"));
