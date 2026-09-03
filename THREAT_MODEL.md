# Vaultify — Threat Model

This document describes what Vaultify protects, who it protects it from, and
how each part of the system holds up against realistic attacks. It follows
the zero-knowledge principle established in the architecture: **the server
should never be able to read a user's vault, under any circumstance.**

## 1. What We're Protecting (Assets)

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Master Password | Only in the user's head, briefly in browser memory during login | Critical — recovers everything if leaked |
| Encryption Key | Derived in-browser, held in memory only while logged in | Critical — decrypts the vault |
| Vault contents (saved site/username/password entries) | Encrypted blob in MongoDB | Critical |
| Auth Key | Derived in-browser, sent to server, stored in MongoDB | Moderate — can't decrypt anything, but is a login credential |
| Salt | Stored in MongoDB, sent to browser before login | Low — not secret by design |
| 2FA secret | Stored in MongoDB | High — combined with a stolen Auth Key, this could allow account takeover |
| Session token (JWT) | Browser localStorage, expires after 1 hour | Moderate — allows API access while valid |

## 2. Trust Boundaries

```
┌─────────────────────────┐        ┌─────────────────────────┐
│   BROWSER (trusted)      │        │   SERVER (untrusted)     │
│                          │        │                          │
│  Master Password         │        │  Auth Key                │
│  Encryption Key          │  ───►  │  Salt                     │
│  Plaintext vault entries │        │  2FA secret               │
│                          │        │  Encrypted blob           │
└─────────────────────────┘        └─────────────────────────┘
```

The server is deliberately treated as **untrusted** for confidentiality
purposes — it's assumed an attacker could fully compromise it (database
dump, source code access, or a malicious admin) and still learn nothing
about any user's actual passwords.

## 3. Threat Scenarios

### 3.1 Server database is breached
**Attack:** An attacker gains full read access to MongoDB (stolen
credentials, misconfigured access, insider threat).
**What they get:** Usernames, Auth Keys, salts, 2FA secrets, and encrypted
blobs (`{iv, ciphertext}` hex strings).
**What they can't do:** Decrypt any vault. The Encryption Key is never
stored anywhere the server can reach — it exists only in browser memory
during an active session and is derived from a password the server never
sees.
**Residual risk:** An attacker with the 2FA secret and a stolen Auth Key
could generate valid 2FA codes and pass authentication — but this still
does not grant access to the encrypted vault contents, since the
Encryption Key is a *separate* derivation the attacker cannot reproduce
without the Master Password.

### 3.2 Network eavesdropping (man-in-the-middle)
**Attack:** An attacker intercepts traffic between browser and server.
**Mitigation:** All traffic should run over HTTPS/TLS in production
(current local development runs over plain HTTP, which is acceptable
only because it's confined to `localhost`). Over TLS, the Auth Key,
salt, and encrypted blob are protected in transit. The Master Password
and Encryption Key never travel over the network at all, so there is
nothing to intercept even in the worst case of a TLS failure.

### 3.3 Stolen or leaked session token (JWT)
**Attack:** An attacker obtains a valid JWT (e.g. via a compromised
browser extension, XSS, or a shared/public computer).
**Impact:** The attacker can call `/vault` and retrieve the *encrypted*
blob, and could call `PUT /vault` to overwrite it — but cannot decrypt
existing data or produce validly-encrypted new data without the
Encryption Key.
**Mitigation:** Tokens expire after 1 hour, limiting the window of
misuse. Logout explicitly clears the token from `localStorage` and wipes
the Encryption Key from memory.
**Limitation:** A malicious blob overwrite (denial-of-service against the
user's own data) is still possible with a stolen token, since the server
cannot distinguish a legitimate encrypted update from an attacker's
garbage write. Mitigating this fully would require additional integrity
controls beyond this project's current scope.

### 3.4 Brute-force login attempts
**Attack:** An attacker repeatedly guesses Auth Keys or Master Passwords.
**Mitigation:** PBKDF2 with 100,000 iterations makes each derivation
attempt computationally expensive, meaningfully slowing offline
brute-force attempts against a stolen Auth Key or salt.
**Limitation:** The current backend does not implement rate-limiting or
account lockout on the `/login` route, meaning an attacker could still
attempt many *online* guesses in sequence. This is a known gap — a
production deployment should add rate-limiting (e.g. via middleware like
`express-rate-limit`).

### 3.5 Weak or reused Master Password
**Attack:** A user chooses a common or previously-breached password.
**Reality:** Vaultify's cryptography cannot protect a user from a weak
Master Password — PBKDF2 slows down guessing but does not prevent it if
the password itself is low-entropy. This is a fundamental limitation of
any password-based system, not specific to Vaultify.
**Mitigation (not yet implemented):** A password strength meter at
registration would help users choose stronger Master Passwords.

### 3.6 Malicious or compromised frontend code
**Attack:** An attacker injects malicious JavaScript (e.g. via a
supply-chain attack on a dependency, or a compromised CDN) that reads the
Encryption Key from memory while a user is logged in.
**Reality:** This is the hardest threat for *any* browser-based
zero-knowledge system to fully defend against — if the client-side code
itself is compromised, the zero-knowledge guarantee breaks down, since
the malicious code runs with the same access as the legitimate app.
**Mitigation:** Keep dependencies minimal and audited, avoid loading
third-party scripts on pages that handle the Encryption Key, and consider
a Content Security Policy in production.

### 3.7 Lost or stolen 2FA device
**Attack:** A user loses the phone running their authenticator app.
**Impact:** The user cannot complete login (Auth Key alone is no longer
sufficient once 2FA is enabled).
**Limitation:** No account-recovery or backup-codes flow currently
exists. This is a known gap — see Section 5.

### 3.8 Forgotten Master Password
**This is the central design trade-off of Vaultify, not a bug.**
If a user forgets their Master Password, their vault **cannot be
recovered by anyone, including the Vaultify team.** There is no "reset
password" flow, because implementing one would require the server to be
capable of decrypting (or re-encrypting) the vault — which would mean
the server *could* read user data, breaking the zero-knowledge
guarantee entirely. The absence of account recovery is the direct,
necessary cost of the security model this project is built around.

## 4. Out of Scope

- **Malware on the user's own device** (e.g. a keylogger capturing the
  Master Password as it's typed). No software running on a compromised
  endpoint can fully protect against this.
- **Physical device theft** while a session is actively unlocked.
- **Social engineering / phishing** the user into typing their Master
  Password into a fake site.
- **Denial-of-service attacks** against the MongoDB Atlas or hosting
  infrastructure itself.

## 5. Known Limitations & Future Work

- No rate-limiting on `/login` (Section 3.4)
- No account recovery / 2FA backup codes (Section 3.7)
- No password strength meter at registration (Section 3.5)
- Encrypted blob integrity is not independently verified against
  unauthorized overwrites by a holder of a stolen token (Section 3.3)
- Production deployment must enforce HTTPS; current setup assumes local,
  trusted-network development only
