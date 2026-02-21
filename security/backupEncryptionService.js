"use strict";

const crypto = require("crypto");

const REQUIRED_KEY_BYTES = 32; // AES-256

const decodeKey = (rawValue, keyName) => {
    const raw = String(rawValue || "");
    if (!raw) {
        throw new Error(`${keyName} is required`);
    }

    let buffer;
    if (/^[0-9a-fA-F]+$/.test(raw) && raw.length === REQUIRED_KEY_BYTES * 2) {
        buffer = Buffer.from(raw, "hex");
    } else {
        buffer = Buffer.from(raw, "base64");
    }

    if (buffer.length !== REQUIRED_KEY_BYTES) {
        throw new Error(`${keyName} must be ${REQUIRED_KEY_BYTES} bytes (got ${buffer.length})`);
    }

    return buffer;
};

const resolveGlobalBackupKey = () => {
    const backupKey = process.env.BACKUP_ENCRYPTION_KEY;
    const defaultKey = process.env.ENCRYPTION_KEY;

    if (backupKey) {
        return {
            key: decodeKey(backupKey, "BACKUP_ENCRYPTION_KEY"),
            keyReference: "BACKUP_ENCRYPTION_KEY",
        };
    }

    return {
        key: decodeKey(defaultKey, "ENCRYPTION_KEY"),
        keyReference: "ENCRYPTION_KEY",
    };
};

const encryptText = (plainText) => {
    const { key, keyReference } = resolveGlobalBackupKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    const plaintextBuffer = Buffer.from(String(plainText), "utf8");
    const encrypted = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
    const tag = cipher.getAuthTag();
    const payload = Buffer.concat([iv, tag, encrypted]).toString("base64");

    return {
        payload,
        algorithm: "aes-256-gcm",
        keyReference,
    };
};

const decryptText = (payload) => {
    const { key, keyReference } = resolveGlobalBackupKey();
    const raw = Buffer.from(String(payload || ""), "base64");
    if (raw.length < 28) {
        throw new Error("Invalid encrypted payload");
    }

    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ciphertext = raw.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    return {
        text: decrypted.toString("utf8"),
        keyReference,
    };
};

const encryptBackupObject = (backupObject) => {
    const serialized = JSON.stringify(backupObject);
    return encryptText(serialized);
};

const decryptBackupObject = (payload) => {
    const { text, keyReference } = decryptText(payload);
    return {
        data: JSON.parse(text),
        keyReference,
    };
};

module.exports = {
    encryptBackupObject,
    decryptBackupObject,
    encryptText,
    decryptText,
};
