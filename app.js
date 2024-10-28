const express = require("express");
const path = require("path");
const fs = require("fs");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const port = 3457;

// MongoDB Connection
mongoose.connect("mongodb://localhost:27017/authApp")
.then(() => console.log("MDB connected"));

const User = mongoose.model("User", new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  subject: String,
  message: String,
  password: String,
}));

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve Static Files
app.use(express.static(path.join(__dirname, "public")));

// Render Registration and Login Pages
app.get("/register", (req, res) => res.render("register"));
app.get("/login", (req, res) => res.render("login"));

// Registration Route
app.post("/register", async (req, res) => {
  const { name, email, phone, subject, message, password } = req.body;
  if (!name || !email || !phone || !subject || !message || !password) {
    return res.status(400).send("All fields are required");
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ name, email, phone, subject, message, password: hashedPassword });
  await user.save();
  
  res.redirect("/login");
});

// Login Route with JWT Authentication
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ email: username });
  
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).send("Invalid credentials");
  }
  
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.cookie("token", token, { httpOnly: true }).redirect("/welcome");
});

// Welcome Page (Protected Route)
app.get("/welcome", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.redirect("/login");
    res.render("welcome", { user: decoded });
  });
});

// Logout Route
app.post("/logout", (req, res) => {
  res.clearCookie("token").redirect("/login");
});

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
