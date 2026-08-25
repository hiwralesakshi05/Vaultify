/**
 * server.js
 * ---------
 * Vaultify's "dumb" backend server.
 *
 * Reminder: this server NEVER sees the real Master Password. It only
 * ever sees the Auth Key (derived in the browser via PBKDF2) and the
 * Encrypted Blob (gibberish it can't read).
 */

require("dotenv").config(); // loads variables from .env into process.env

const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
 // now pulled from .env, not hardcoded

app.use(express.json());

// --- FAKE "DATABASE" (temporary — swapped for a real one in the next step) ---
const fakeUsersDB = {
  shubham: {
    authKey: "demo-auth-key-12345",
  },
};

const fakeVaultDB = {};

app.get("/", (req, res) => {
  res.send("Vaultify backend is running! 🔐");
});

app.post("/login", (req, res) => {
  const { username, authKey } = req.body;
  const user = fakeUsersDB[username];

  if (!user || user.authKey !== authKey) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  const token = jwt.sign({ username: username }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ success: true, message: "Login successful!", token: token });
});

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.username = decoded.username;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
}

app.get("/vault", requireAuth, (req, res) => {
  const blob = fakeVaultDB[req.username];

  if (!blob) {
    return res.json({ success: true, blob: null, message: "No vault saved yet" });
  }

  res.json({ success: true, blob: blob });
});

app.put("/vault", requireAuth, (req, res) => {
  const { blob } = req.body;
  fakeVaultDB[req.username] = blob;
  res.json({ success: true, message: "Vault saved!" });
});

app.listen(PORT, () => {
  console.log(`Vaultify server listening on http://localhost:${PORT}`);
});