# Vaultify 🔐

A **Zero-Knowledge Password Manager**. Vaultify is built so that even the
server storing your data can never read it — all encryption and decryption
happens entirely in your browser, using your Master Password. The server
only ever sees encrypted gibberish.

> If the server is hacked, the attacker finds nothing but unreadable noise.

## 🌐 Live Demo

- **App:** [vaultify-frontend-354w.onrender.com](https://vaultify-frontend-354w.onrender.com)
- **API:** [vaultify-do0g.onrender.com](https://vaultify-do0g.onrender.com)

*(Hosted on Render's free tier — the API stays warm via a scheduled
keep-alive ping, so there's no cold-start delay.)*

## How It Works

Your Master Password is stretched into **two separate, unrelated keys**
using PBKDF2 (100,000 iterations, SHA-256) — a slow, salted key derivation
function that resists brute-force attacks.

- **Auth Key** → sent to the server, used only to verify login
- **Encryption Key** → never leaves your browser, used to lock/unlock your vault

Because these two keys are mathematically unrelated outputs of the same
one-way function, stealing one (e.g. from a hacked database) gives an
attacker zero ability to derive the other.

![Architecture Diagram](./architecture-diagram.svg)

## Crypto Library (`crypto.js`)

The core cryptography lives in [`crypto.js`](./crypto.js):

| Function | Purpose |
|---|---|
| `generateSalt()` | Creates a random 16-byte salt (unique per user) |
| `deriveKeyFromPassword(password, salt)` | Derives the Encryption Key via PBKDF2 |
| `deriveAuthKey(password, salt)` | Derives a *separate*, unrelated Auth Key |
| `encryptData(key, data)` | Encrypts a vault entry with AES-256-GCM |
| `decryptData(key, iv, ciphertext)` | Decrypts a vault entry back to the original object |

## Features

- **Zero-knowledge encryption** — AES-256-GCM, keys derived client-side via PBKDF2
- **Real user accounts** — Register/Login backed by MongoDB Atlas
- **Password generator** — cryptographically random, via `crypto.getRandomValues`
- **Two-Factor Authentication** — TOTP, compatible with Google Authenticator/Authy
- **Session-based auth** — JWT tokens, 1-hour expiry
- **Sensitive data clearing** — Encryption Key and vault entries wiped from memory on logout

## Tech Stack

- **Frontend:** React (Vite), deployed as a static site on Render
- **Backend:** Node.js, Express, deployed as a web service on Render
- **Cryptography:** Web Crypto API — PBKDF2, AES-256-GCM, SHA-256
- **Database:** MongoDB Atlas
- **2FA:** TOTP via `otplib`
- **Auth:** JSON Web Tokens (`jsonwebtoken`)

## Project Status

- [x] **Week 1 — Crypto Logic:** PBKDF2 key derivation + AES-256-GCM encrypt/decrypt
- [x] **Week 2 — Backend & Sync:** Node.js API, Auth Key login flow, save/load vault endpoints
- [x] **Week 3 — The Manager UI:** Dashboard, Add Password form, Password Generator, real client-side encryption
- [x] **Week 4 — 2FA & Polish:** TOTP 2FA, security audit (no sensitive data logged)
- [x] **Deployment:** Live on Render, frontend + backend

## Security

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the full threat model —
covering trust boundaries, 8 realistic attack scenarios, and known
limitations.

### What if I forget my Master Password?

Your data is lost forever — and that's by design, not a flaw. Since the
server never has your password or your Encryption Key, there is no
"reset password" flow that could restore your vault. Any such flow would
mean the server is capable of unlocking your data — which would break the
zero-knowledge guarantee entirely.

## Repositories

- **Backend:** this repo
- **Frontend:** [vaultify-frontend](https://github.com/hiwralesakshi05/vaultify-frontend)
