/**
 * server.js
 * ---------
 * Vaultify's "dumb" backend server.
 *
 * Reminder: this server NEVER sees the real Master Password. It only
 * ever sees the Auth Key (derived in the browser via PBKDF2) and the
 * Encrypted Blob (gibberish it can't read).
 */

const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();

const PORT = 3000;

// Temporary — will move to a .env file in a later step.
const JWT_SECRET = "temporary-dev-secret-change-me";

app.use(express.json());

// --- FAKE "DATABASE" (temporary — swapped for a real one in a later step) ---
const fakeUsersDB = {
  shubham: {
    authKey: "demo-auth-key-12345",
  },
};

// Where each user's encrypted vault blob will live, once they save one.
// Empty for now — nobody has saved a vault yet.
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

/**
 * The "bouncer" middleware. Runs BEFORE any route it's attached to.
 * Checks for a valid JWT in the request headers before letting the
 * request continue.
 */
function requireAuth(req, res, next) {
  // Tokens are conventionally sent as: "Authorization: Bearer <token>"
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "No token provided" });
  }

  const token = authHeader.split(" ")[1]; // grabs the part AFTER "Bearer "

  try {
    // This throws an error if the token is invalid, tampered with, or expired.
    const decoded = jwt.verify(token, JWT_SECRET);
    req.username = decoded.username; // attach it, so routes below know who's asking
    next(); // token is good — let the request through to the real route
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
}

// GET /vault — returns the logged-in user's encrypted blob.
// Notice requireAuth is listed BEFORE the route logic — that's how
// Express knows to run the bouncer check first.
app.get("/vault", requireAuth, (req, res) => {
  const blob = fakeVaultDB[req.username];

  if (!blob) {
    return res.json({ success: true, blob: null, message: "No vault saved yet" });
  }

  res.json({ success: true, blob: blob });
});

// PUT /vault — saves/overwrites the logged-in user's encrypted blob.
app.put("/vault", requireAuth, (req, res) => {
  const { blob } = req.body;
  fakeVaultDB[req.username] = blob;
  res.json({ success: true, message: "Vault saved!" });
});

app.listen(PORT, () => {
  console.log(`Vaultify server listening on http://localhost:${PORT}`);
});