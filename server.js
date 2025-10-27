// server.js
const express = require("express");
const app = express();
app.use(express.json());

app.post("/register", (req, res) => {
  const { email, password } = req.body;
  // save to PostgreSQL, etc.
  res.send("User registered!");
});

app.listen(3000, () => console.log("Backend running on port 3000"));