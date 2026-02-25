const parseExpiresInToSeconds = (value) => {
    const raw = String(value || "").trim();
    if (!raw) return 12 * 60 * 60;

    if (/^\d+$/.test(raw)) {
        return Number.parseInt(raw, 10);
    }

    const match = raw.match(/^(\d+)([smhd])$/i);
    if (!match) return 12 * 60 * 60;

    const amount = Number.parseInt(match[1], 10);
    const unit = match[2].toLowerCase();
    const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
    return amount * multipliers[unit];
};

const JWT_SECRET = String(
    process.env.JWT_SECRET ||
    process.env.AUTH_TOKEN_SECRET ||
    process.env.AUTH_PEPPER ||
    ""
).trim();

const JWT_ISSUER = String(process.env.JWT_ISSUER || "studentcheck-server").trim();
const JWT_AUDIENCE = String(process.env.JWT_AUDIENCE || "studentcheck-frontend").trim();
const JWT_EXPIRES_IN_SECONDS = parseExpiresInToSeconds(process.env.JWT_EXPIRES_IN || "12h");

module.exports = {
    JWT_SECRET,
    JWT_ISSUER,
    JWT_AUDIENCE,
    JWT_EXPIRES_IN_SECONDS,
};
