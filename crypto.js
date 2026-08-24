/**
 * crypto.js
 * ---------
 * Vaultify's Zero-Knowledge Crypto Library.
 *
 * This file contains ALL the cryptography for Vaultify. Nothing in here
 * ever talks to a server — everything runs 100% client-side, in the
 * user's browser, using the built-in Web Crypto API.
 *
 * Flow:
 *   Master Password
 *        │
 *        ▼  deriveKeyFromPassword()
 *   Encryption Key  (never leaves the browser)
 *        │
 *        ├──► encryptData()   → locks a vault entry into gibberish
 *        └──► decryptData()   → unlocks it back to the original JSON
 */

/**
 * Turns a plain-text Master Password into a strong AES-256 key using
 * PBKDF2 (Password-Based Key Derivation Function 2).
 *
 * @param {string} password - The user's master password (plain text)
 * @param {Uint8Array} salt - A random 16-byte salt (unique per user,
 *                            generated once at signup and stored — it's
 *                            NOT secret, just needs to be unique)
 * @returns {Promise<CryptoKey>} An AES-256-GCM key ready to encrypt/decrypt
 */
async function deriveKeyFromPassword(password, salt) {
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);

  // Step 1: Load the password bytes as "raw material" for PBKDF2.
  // extractable = false means the raw password can never be pulled
  // back out of this object once loaded — a security best practice.
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveKey", "deriveBits"]
  );

  // Step 2: Stretch that material into a real 256-bit AES key.
  // 100,000 iterations deliberately slows down brute-force attacks —
  // going higher (e.g. 300,000+) is even safer but slower for the user.
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return derivedKey;
}

/**
 * Generates a fresh random salt. Call this ONCE per user, at signup,
 * and store the result alongside their account (it's safe to store
 * in plain text — it's not a secret, just needs to be unique).
 *
 * @returns {Uint8Array} A random 16-byte salt
 */
function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Encrypts a JavaScript object (e.g. one vault entry) into gibberish
 * bytes, ready to be sent to the "dumb server" for storage.
 *
 * @param {CryptoKey} key - The Encryption Key from deriveKeyFromPassword()
 * @param {Object} data - The plain data to encrypt (e.g. {site, username, password})
 * @returns {Promise<{iv: Uint8Array, ciphertext: Uint8Array}>}
 *          The IV (safe to store openly) and the encrypted bytes
 */
async function encryptData(key, data) {
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(JSON.stringify(data));

  // A fresh random IV (Initialization Vector) is required EVERY time
  // you encrypt, even with the same key — this stops identical data
  // from ever producing identical-looking ciphertext.
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    plaintextBytes
  );

  return {
    iv: iv,
    ciphertext: new Uint8Array(ciphertextBuffer),
  };
}

/**
 * Decrypts data that was locked with encryptData(), reversing it back
 * into the original JavaScript object.
 *
 * @param {CryptoKey} key - The SAME Encryption Key used to encrypt
 * @param {Uint8Array} iv - The SAME IV that was produced during encryption
 * @param {Uint8Array} ciphertext - The encrypted bytes
 * @returns {Promise<Object>} The original decrypted object
 */
async function decryptData(key, iv, ciphertext) {
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  const decryptedText = decoder.decode(decryptedBuffer);
  return JSON.parse(decryptedText);
}

// Export everything so other files (e.g. the React app, or your
// console tests) can import and use these functions.
export { deriveKeyFromPassword, generateSalt, encryptData, decryptData };
