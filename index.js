const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const validator = require("validator");
const express = require("express");
const bodyParser = require("body-parser");
const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.set("views", __dirname + "/views");

app.use(helmet());

// Fake DB (array)
let users = [];

// Signup page
app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", (req, res) => {
  const { username, password } = req.body;

  // Validate email format
  if (!validator.isEmail(username)) {
    return res.status(400).send("❌ Invalid email format");
  }

  // Validate strong password
  if (!validator.isStrongPassword(password)) {
    return res.status(400).send("❌ Weak password. Use mix of letters, numbers & symbols");
  }

  // Hash password before saving
bcrypt.hash(password, 10, (err, hashedPassword) => {
  if (err) return res.status(500).send("Error hashing password");

  users.push({ username, password: hashedPassword });
  res.send("✅ User registered securely: " + username);
});

});
// Show login form
app.get("/login", (req, res) => {
  res.render("login");
});
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.send("❌ Invalid credentials");
  }

  // Compare entered password with hashed password
  bcrypt.compare(password, user.password, (err, result) => {
    if (err) return res.status(500).send("Error during login");

    if (result) {
      // Generate JWT token
      const token = jwt.sign(
        { username: user.username },
        "super-secret-key",   // ⚠️ in real apps, use env variable
        { expiresIn: "1h" }
      );

      res.json({ message: "✅ Login successful", token: token });
    } else {
      res.send("❌ Invalid credentials");
    }
  });
});

app.listen(3000, () => console.log("App running at http://localhost:3000"));
