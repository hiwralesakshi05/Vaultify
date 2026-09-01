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
const mongoose = require("mongoose");
const cors = require("cors");
const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET; // now pulled from .env, not hardcoded

app.use(express.json());
app.use(cors()); // allows the React frontend (different port) to call this API

// Connect to MongoDB Atlas using the connection string from .env
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("MongoDB connection error:", err));

// --- DATABASE SCHEMAS ---

// Defines the shape of a User document in MongoDB.
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  authKey: { type: String, required: true },
  salt: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

// Defines the shape of a Vault document — one per user, holding
// their encrypted blob.
const vaultSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  blob: { type: String, default: null },
});
const Vault = mongoose.model("Vault", vaultSchema);

app.get("/", (req, res) => {
  res.send("Vaultify backend is running! 🔐");
});

// REGISTER route — creates a new user in the database.
app.post("/register", async (req, res) => {
  const { username, authKey, salt } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Username already taken" });
    }

    const newUser = new User({ username, authKey, salt });
    await newUser.save();

    res.json({ success: true, message: "User registered!" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});
// Returns a user's salt so the browser can derive login keys locally.
// Not sensitive — a salt is meant to be public.
app.get("/salt/:username", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({ success: true, salt: user.salt });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});
// LOGIN route — checks the real database, issues a JWT.
app.post("/login", async (req, res) => {
  const { username, authKey } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user || user.authKey !== authKey) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign({ username: username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ success: true, message: "Login successful!", token: token });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

/**
 * The "bouncer" middleware. Runs BEFORE any route it's attached to.
 */
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

// GET /vault — returns the logged-in user's encrypted blob.
app.get("/vault", requireAuth, async (req, res) => {
  try {
    const vault = await Vault.findOne({ username: req.username });

    if (!vault) {
      return res.json({ success: true, blob: null, message: "No vault saved yet" });
    }

    res.json({ success: true, blob: vault.blob });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

// PUT /vault — saves/overwrites the logged-in user's encrypted blob.
app.put("/vault", requireAuth, async (req, res) => {
  const { blob } = req.body;

  try {
    await Vault.findOneAndUpdate(
      { username: req.username },
      { blob: blob },
      { upsert: true }
    );

    res.json({ success: true, message: "Vault saved!" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Vaultify server listening on http://localhost:${PORT}`);
});