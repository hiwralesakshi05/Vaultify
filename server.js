/**
 * server.js
 * ---------
 * Vaultify's "dumb" backend server. This file will eventually handle:
 *   - Login (verifying the Auth Key)
 *   - Saving/loading the encrypted vault blob
 *
 * For now, this is just a minimal starting point to prove the server
 * runs at all — one test route, nothing more.
 */

const express = require("express");
const app = express();

const PORT = 3000;

// A single test route. Visiting http://localhost:3000 in a browser
// will trigger this and send back a simple message.
app.get("/", (req, res) => {
  res.send("Vaultify backend is running! 🔐");
});

app.listen(PORT, () => {
  console.log(`Vaultify server listening on http://localhost:${PORT}`);
});
