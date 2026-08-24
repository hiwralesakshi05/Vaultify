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

// Secret used to SIGN tokens — like the stamp that makes a wristband
// unforgeable. In a real deployed app this would live in a .env file,
// never hardcoded like this. We'll fix that in a later step.
const JWT_SECRET = "temporary-dev-secret-change-me";

app.use(express.json());

// --- FAKE "DATABASE" (temporary — swapped for a real one in a later step) ---
const fakeUsersDB = {
  shubham: {
    authKey: "demo-auth-key-12345",
  },
};

app.get("/", (req, res) => {
  res.send("Vaultify backend is running! 🔐");
});

// LOGIN route — now issues a real JWT on success.
app.post("/login", (req, res) => {
  const { username, authKey } = req.body;

  const user = fakeUsersDB[username];

  if (!user || user.authKey !== authKey) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  // Create the "wristband". We embed the username inside it so later,
  // when this token comes back to us, we know WHO it belongs to.
  // expiresIn: "1h" means the wristband stops working after 1 hour —
  // forcing the user to log in again (a good security habit).
  const token = jwt.sign(
    { username: username },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ success: true, message: "Login successful!", token: token });
});

app.listen(PORT, () => {
  console.log(`Vaultify server listening on http://localhost:${PORT}`);
});