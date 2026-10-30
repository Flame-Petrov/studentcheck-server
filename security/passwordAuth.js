const crypto = require("crypto");
const argon2 = require("argon2");

const ARGON2_ALGORITHM = "argon2id_v1";
const ARGON2_OPTIONS = {
    type: argon2.argon2id,
    timeCost: 3,
    memoryCost: 19456,
    parallelism: 1,
};

const LEGACY_LOOKUP_HASH_REGEX = /^[a-f0-9]{64}$/i;

const toStringValue = (value) => (typeof value === "string" ? value : String(value == null ? "" : value));

const timingSafeStringEqual = (left, right) => {
    if (typeof left !== "string" || typeof right !== "string") return false;

    const leftBuffer = Buffer.from(left, "utf8");
    const rightBuffer = Buffer.from(right, "utf8");
    if (leftBuffer.length !== rightBuffer.length) return false;

    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
};

const getAuthPepper = () => {
    const pepper = toStringValue(process.env.AUTH_PEPPER).trim();
    if (!pepper) {
        throw new Error("AUTH_PEPPER is required");
    }
    return pepper;
};

const withPepper = (password, pepper = getAuthPepper()) => {
    return `${pepper}\u0000${toStringValue(password)}`;
};

const isArgon2Record = ({ passwordHash, hashAlgorithm }) => {
    if (typeof hashAlgorithm === "string" && hashAlgorithm.toLowerCase() === ARGON2_ALGORITHM) {
        return true;
    }
    return typeof passwordHash === "string" && passwordHash.startsWith("$argon2id$");
};

const shouldUseLegacyLookupHash = (passwordHash) => {
    if (typeof passwordHash !== "string" || !passwordHash) return false;
    return LEGACY_LOOKUP_HASH_REGEX.test(passwordHash);
};

const hashPassword = async (plainPassword) => {
    if (typeof plainPassword !== "string" || !plainPassword) {
        throw new Error("Password is required");
    }

    return argon2.hash(withPepper(plainPassword), ARGON2_OPTIONS);
};

const verifyArgon2Hash = async (plainPassword, passwordHash) => {
    if (typeof plainPassword !== "string" || !plainPassword) return false;
    if (typeof passwordHash !== "string" || !passwordHash) return false;

    try {
        return await argon2.verify(passwordHash, withPepper(plainPassword));
    } catch {
        return false;
    }
};

const verifyLegacyPassword = ({
    inputPassword,
    rowPassword,
    rowPasswordHash,
    legacyHashVerifier,
    legacyDecryptor,
}) => {
    if (typeof inputPassword !== "string" || !inputPassword) return false;

    if (typeof legacyHashVerifier === "function" && shouldUseLegacyLookupHash(rowPasswordHash)) {
        const computed = legacyHashVerifier(inputPassword);
        if (timingSafeStringEqual(computed, rowPasswordHash)) {
            return true;
        }
    }

    if (typeof rowPassword === "string" && rowPassword && timingSafeStringEqual(rowPassword, inputPassword)) {
        return true;
    }

    if (typeof legacyDecryptor === "function" && typeof rowPassword === "string" && rowPassword) {
        let decryptedPassword = null;
        try {
            decryptedPassword = legacyDecryptor(rowPassword);
        } catch {
            decryptedPassword = null;
        }
        if (typeof decryptedPassword === "string" && decryptedPassword && timingSafeStringEqual(decryptedPassword, inputPassword)) {
            return true;
        }
    }

    return false;
};

const verifyPasswordWithMigration = async ({
    inputPassword,
    rowPassword,
    rowPasswordHash,
    rowHashAlgorithm,
    legacyHashVerifier,
    legacyDecryptor,
}) => {
    if (typeof inputPassword !== "string" || !inputPassword) {
        return { isValid: false, needsMigration: false, matchedWith: null };
    }

    if (isArgon2Record({ passwordHash: rowPasswordHash, hashAlgorithm: rowHashAlgorithm })) {
        const isValid = await verifyArgon2Hash(inputPassword, rowPasswordHash);
        return {
            isValid,
            needsMigration: false,
            matchedWith: isValid ? "argon2id" : null,
        };
    }

    const legacyValid = verifyLegacyPassword({
        inputPassword,
        rowPassword,
        rowPasswordHash,
        legacyHashVerifier,
        legacyDecryptor,
    });

    return {
        isValid: legacyValid,
        needsMigration: legacyValid,
        matchedWith: legacyValid ? "legacy" : null,
    };
};

// Accounts carried over from the old database keep their old credentials as
// "legacy-v1:<lookup hash>:<encrypted or plain password>" until their next login,
// when the server replaces them with an argon2 hash.
const LEGACY_PASSWORD_PREFIX = "legacy-v1:";

const verifyStoredPassword = async ({
    inputPassword,
    storedHash,
    legacyHashVerifier,
    legacyDecryptor,
}) => {
    const stored = typeof storedHash === "string" ? storedHash : "";
    if (!stored.startsWith(LEGACY_PASSWORD_PREFIX)) {
        return verifyPasswordWithMigration({
            inputPassword,
            rowPassword: null,
            rowPasswordHash: stored,
            rowHashAlgorithm: null,
            legacyHashVerifier,
            legacyDecryptor,
        });
    }

    const legacyPart = stored.slice(LEGACY_PASSWORD_PREFIX.length);
    const separatorIndex = legacyPart.indexOf(":");
    const lookupHash = separatorIndex === -1 ? legacyPart : legacyPart.slice(0, separatorIndex);
    const oldPassword = separatorIndex === -1 ? "" : legacyPart.slice(separatorIndex + 1);
    return verifyPasswordWithMigration({
        inputPassword,
        rowPassword: oldPassword || null,
        rowPasswordHash: lookupHash || null,
        rowHashAlgorithm: null,
        legacyHashVerifier,
        legacyDecryptor,
    });
};

module.exports = {
    LEGACY_PASSWORD_PREFIX,
    hashPassword,
    verifyPasswordWithMigration,
    verifyStoredPassword,
};
