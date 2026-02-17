const crypto = require("crypto");

const REQUIRED_AES_KEY_BYTES = 32; // AES-256
const REQUIRED_HMAC_KEY_BYTES = 32;

// Decode env key as hex or base64; fail fast if invalid
function decodeKey(raw, name, requiredBytes) {
    if (!raw) {
        throw new Error(`${name} is required`);
    }

    let buf;
    if (/^[0-9a-fA-F]+$/.test(raw) && raw.length === requiredBytes * 2) {
        buf = Buffer.from(raw, "hex");
    } else {
        buf = Buffer.from(raw, "base64");
    }

    if (buf.length !== requiredBytes) {
        throw new Error(`${name} must be ${requiredBytes} bytes (got ${buf.length})`);
    }

    return buf;
}

const ENCRYPTION_KEY = decodeKey(
    process.env.ENCRYPTION_KEY || "",
    "ENCRYPTION_KEY",
    REQUIRED_AES_KEY_BYTES
);

const LOOKUP_HASH_KEY = decodeKey(
    process.env.LOOKUP_HASH_KEY || "",
    "LOOKUP_HASH_KEY",
    REQUIRED_HMAC_KEY_BYTES
);

// Normalize for consistent hashing / encryption (e.g. emails, faculty numbers)
const normalize = (value) =>
    typeof value === "string"
        ? value.trim().toLowerCase()
        : String(value || "").trim().toLowerCase();

/**
 * Encrypt a string using AES-256-GCM.
 * Format: base64([IV(12)][TAG(16)][CIPHERTEXT])
 */
const encrypt = (plain) => {
    if (plain == null) return null;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);

    const plaintext = Buffer.from(String(plain), "utf8");
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const payload = Buffer.concat([iv, tag, encrypted]).toString("base64");
    return payload;
};

/**
 * Decrypt a value produced by encrypt().
 */
const decrypt = (payload) => {
    if (!payload) return null;

    const buf = Buffer.from(payload, "base64");
    if (buf.length < 12 + 16) {
        throw new Error("Invalid encrypted payload");
    }

    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ciphertext = buf.subarray(28);

    const decipher = crypto.createDecipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
};

/**
 * Stable HMAC-SHA256 hash for equality lookups.
 * Returns hex string.
 */
const hashForLookup = (value) => {
    const norm = normalize(value);
    const hmac = crypto.createHmac("sha256", LOOKUP_HASH_KEY);
    hmac.update(norm, "utf8");
    return hmac.digest("hex");
};

module.exports = {
    encrypt,
    decrypt,
    hashForLookup,
    normalize,
};

