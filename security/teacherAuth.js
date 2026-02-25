const crypto = require("crypto");

const toBase64Url = (input) => Buffer.from(input).toString("base64url");
const fromBase64UrlJson = (value) => JSON.parse(Buffer.from(value, "base64url").toString("utf8"));

const signAuthToken = ({ payload, secret }) => {
    const header = { alg: "HS256", typ: "JWT" };
    const encodedHeader = toBase64Url(JSON.stringify(header));
    const encodedPayload = toBase64Url(JSON.stringify(payload));
    const data = `${encodedHeader}.${encodedPayload}`;
    const signature = crypto
        .createHmac("sha256", secret)
        .update(data)
        .digest("base64url");
    return `${data}.${signature}`;
};

const verifyAuthToken = ({ token, secret }) => {
    try {
        const parts = String(token || "").split(".");
        if (parts.length !== 3) return null;
        const [encodedHeader, encodedPayload, signature] = parts;
        const data = `${encodedHeader}.${encodedPayload}`;
        const expectedSignature = crypto
            .createHmac("sha256", secret)
            .update(data)
            .digest("base64url");
        if (signature !== expectedSignature) return null;

        const header = fromBase64UrlJson(encodedHeader);
        if (header.alg !== "HS256" || header.typ !== "JWT") return null;

        const payload = fromBase64UrlJson(encodedPayload);
        if (!payload || typeof payload !== "object") return null;
        if (payload.exp && Math.floor(Date.now() / 1000) > Number(payload.exp)) return null;
        return payload;
    } catch {
        return null;
    }
};

const parseAuthorizationHeader = (authorizationHeader) => {
    const raw = String(authorizationHeader || "").trim();
    if (!raw) return { ok: false, error: "Missing bearer token" };

    const parts = raw.split(/\s+/);
    if (parts.length !== 2 || parts[0] !== "Bearer") {
        return { ok: false, error: "Invalid bearer token format" };
    }
    if (!parts[1]) return { ok: false, error: "Missing bearer token" };

    return { ok: true, token: parts[1] };
};

module.exports = {
    signAuthToken,
    verifyAuthToken,
    parseAuthorizationHeader,
};
