const PORT = process.env.PORT || 3000;

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const util = require("util");
const { Pool } = require("pg"); // PostgreSQL client
const Stripe = require("stripe");
const { createDbAdapter } = require("./dbAdapter");
const { createStripeService } = require("./stripeService");
const { createBackupHandlers } = require("./backupService");
const { createBillingRouter, createBillingWebhookHandler } = require("./billingRoutes");
const { encryptRaw, decrypt, hashForLookup, hashExactForLookup, normalize } = require("./security/cryptoService");
const { resolveEmailForApi, serializeStudent } = require("./security/decryptors");
const {
    ARGON2_ALGORITHM,
    buildArgon2PasswordFields,
    verifyPasswordWithMigration,
} = require("./security/passwordAuth");
const {
    normalizeEmailInput,
    normalizeFacultyNumberInput,
    isValidEmail,
    isValidFacultyNumber,
    parseAndValidateGroup,
} = require("./security/inputValidation");
const {
    buildCheckEmailHandler,
    buildCheckFacultyNumberHandler,
} = require("./security/studentEndpointHandlers");
const {
    mapRegistrationUniqueViolation,
    insertStudentWithIdCollisionRecovery,
} = require("./security/registrationDb");
const {
    signAuthToken,
    verifyAuthToken,
    parseAuthorizationHeader,
} = require("./security/teacherAuth");
const { buildPostClassStudentsHandler } = require("./security/classStudentsPostHandler");
const {
    JWT_SECRET,
    JWT_ISSUER,
    JWT_AUDIENCE,
    JWT_EXPIRES_IN_SECONDS,
} = require("./security/jwtConfig");
const req = require("express/lib/request");

if (!String(process.env.AUTH_PEPPER || "").trim()) {
    throw new Error("AUTH_PEPPER is required");
}
if (!JWT_SECRET) {
    throw new Error("JWT_SECRET (or AUTH_TOKEN_SECRET) is required");
}

const app = express();

// ----------------- Structured Logging Helpers -----------------
const rawInfo = console.info.bind(console);
const rawWarn = console.warn.bind(console);
const rawError = console.error.bind(console);
const LOG_SEPARATOR = "======================";

const writeLogWithSeparator = (writer, ...args) => {
    writer(...args);
    writer(LOG_SEPARATOR);
};

const LOG_STRING_PREVIEW_CHARS = Number.parseInt(process.env.LOG_STRING_PREVIEW_CHARS || "220", 10);
const LOG_PREVIEW_ARRAY_ITEMS = Number.parseInt(process.env.LOG_PREVIEW_ARRAY_ITEMS || "3", 10);
const LOG_PREVIEW_OBJECT_KEYS = Number.parseInt(process.env.LOG_PREVIEW_OBJECT_KEYS || "12", 10);
const LOG_MAX_DEPTH = Number.parseInt(process.env.LOG_MAX_DEPTH || "4", 10);
const LOG_COMPACT_BREAK = Number.parseInt(process.env.LOG_COMPACT_BREAK || "180", 10);
const OMIT_RESPONSE_BODY_FOR_STATUS = new Set([204, 304]);
const SENSITIVE_LOG_KEYS = new Set([
    "password",
    "password_hash",
    "passwordhash",
    "token",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "authorization",
    "secret",
    "api_key",
    "apikey",
]);

const formatBgTime = (date = new Date()) => {
    const formatter = new Intl.DateTimeFormat("bg-BG", {
        timeZone: "Europe/Sofia",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
    return formatter.format(date);
};

const isSensitiveLogKey = (key) => {
    const normalizedKey = String(key || "")
        .replace(/[^a-zA-Z0-9]/g, "")
        .toLowerCase();
    return (
        SENSITIVE_LOG_KEYS.has(normalizedKey) ||
        normalizedKey.includes("password") ||
        normalizedKey.includes("token") ||
        normalizedKey.includes("secret") ||
        normalizedKey.includes("apikey")
    );
};

const tryParseJsonString = (value) => {
    if (typeof value !== "string") return { ok: false, value };
    const trimmed = value.trim();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
        return { ok: false, value };
    }
    try {
        return { ok: true, value: JSON.parse(trimmed) };
    } catch {
        return { ok: false, value };
    }
};

const summarizeForLog = (value, state = null) => {
    const context = state || { depth: 0, seen: new WeakSet() };
    if (value === null || value === undefined) return value;
    if (typeof value === "number" || typeof value === "boolean") return value;
    if (typeof value === "bigint") return value.toString();
    if (typeof value === "string") {
        if (value.length > LOG_STRING_PREVIEW_CHARS) {
            return `${value.slice(0, LOG_STRING_PREVIEW_CHARS)}...[+${value.length - LOG_STRING_PREVIEW_CHARS} chars]`;
        }
        return value;
    }
    if (value instanceof Date) return value.toISOString();
    if (Buffer.isBuffer(value)) return `[Buffer length=${value.length}]`;
    if (value instanceof Error) {
        return {
            name: value.name,
            message: value.message,
            stack: value.stack,
        };
    }
    if (typeof value === "function") {
        return `[Function ${value.name || "anonymous"}]`;
    }
    if (Array.isArray(value)) {
        const sample = value
            .slice(0, LOG_PREVIEW_ARRAY_ITEMS)
            .map((item) => summarizeForLog(item, { depth: context.depth + 1, seen: context.seen }));
        return {
            count: value.length,
            sample,
        };
    }
    if (typeof value === "object") {
        if (context.seen.has(value)) return "[Circular]";
        context.seen.add(value);
        if (context.depth >= LOG_MAX_DEPTH) {
            return `[Object keys=${Object.keys(value).length}]`;
        }
        const result = {};
        const entries = Object.entries(value).slice(0, LOG_PREVIEW_OBJECT_KEYS);
        for (const [key, childValue] of entries) {
            if (isSensitiveLogKey(key)) {
                result[key] = "[REDACTED]";
                continue;
            }
            result[key] = summarizeForLog(childValue, { depth: context.depth + 1, seen: context.seen });
        }
        const totalKeys = Object.keys(value).length;
        if (totalKeys > entries.length) {
            result._moreKeys = totalKeys - entries.length;
        }
        return result;
    }
    return String(value);
};

const summarizeResponsePayload = (body) => {
    if (body === undefined) return "[none]";
    const parsed = tryParseJsonString(body);
    if (parsed.ok) return summarizeForLog(parsed.value);
    return summarizeForLog(body);
};

const formatFieldValue = (value) => {
    return util.inspect(summarizeForLog(value), {
        depth: LOG_MAX_DEPTH,
        colors: false,
        compact: true,
        breakLength: LOG_COMPACT_BREAK,
        maxArrayLength: LOG_PREVIEW_ARRAY_ITEMS + 2,
        maxStringLength: LOG_STRING_PREVIEW_CHARS,
    });
};

const formatPayloadFields = (payload = {}) => {
    return Object.entries(payload)
        .filter(([, value]) => value !== undefined && value !== null)
        .map(([key, value]) => `${key}=${formatFieldValue(value)}`)
        .join(" ");
};

const shortRequestId = (requestId) => {
    const value = String(requestId || "");
    return value ? value.slice(0, 8) : "n/a";
};

const summarizeRequest = (req, options = {}) => {
    const { includeBody = true } = options;
    const summary = {
        ip: req.ip,
        route: req.route?.path || null,
        params: req.params || {},
        query: req.query || {},
    };

    if (!includeBody) return summary;

    const body = req.body;
    const hasBody = body !== undefined && body !== null && (
        typeof body !== "object" || Array.isArray(body) || Object.keys(body).length > 0
    );
    if (hasBody) {
        summary.body = body;
    }
    return summary;
};

const emitLog = (level, eventName, payload = {}) => {
    const line = `[${level.toUpperCase()} ${formatBgTime()}] ${eventName}`;
    const details = formatPayloadFields(payload);
    const message = details ? `${line} ${details}` : line;
    if (level === "error") {
        writeLogWithSeparator(rawError, message);
        return;
    }
    if (level === "warn") {
        writeLogWithSeparator(rawWarn, message);
        return;
    }
    writeLogWithSeparator(rawInfo, message);
};

const getActionContext = (req) => {
    if (!req.actionContext) {
        req.actionContext = {
            requestId: crypto.randomUUID(),
            actionName: `${req.method} ${req.path || req.originalUrl}`,
            receivedAtMs: Date.now(),
            startLogged: false,
            endLogged: false,
            flowStep: 0,
            responseCaptured: false,
            responseBody: null,
        };
    }
    return req.actionContext;
};

const logActionFlow = (req, stage, data = {}) => {
    const context = getActionContext(req);
    context.flowStep += 1;
    emitLog("info", "ACTION_FLOW", {
        rid: shortRequestId(context.requestId),
        action: context.actionName,
        step: context.flowStep,
        stage,
        data,
    });
};

const logRequestStart = (req, options = {}) => {
    const { note, includeBody = true, actionName } = options;
    const context = getActionContext(req);

    if (actionName) {
        context.actionName = actionName;
    }

    if (!context.startLogged) {
        context.startLogged = true;
        const request = summarizeRequest(req, { includeBody });
        emitLog("info", "ACTION_START", {
            rid: shortRequestId(context.requestId),
            action: context.actionName,
            method: req.method,
            path: req.originalUrl,
            note: note || undefined,
            request,
        });
        return;
    }

    logActionFlow(req, "request_update", {
        note: note || null,
        request: summarizeRequest(req, { includeBody }),
    });
};

const logRequestEnd = (req, res) => {
    const context = getActionContext(req);
    if (context.endLogged) return;
    context.endLogged = true;

    let responseSummary = "[no response body captured]";
    if (context.responseCaptured) {
        if (OMIT_RESPONSE_BODY_FOR_STATUS.has(res.statusCode)) {
            responseSummary = `[omitted for status ${res.statusCode}]`;
        } else {
            responseSummary = summarizeResponsePayload(context.responseBody);
        }
    }

    emitLog("info", "ACTION_END", {
        rid: shortRequestId(context.requestId),
        action: context.actionName,
        status: res.statusCode,
        ms: Date.now() - context.receivedAtMs,
        response: responseSummary,
    });
};

// Structured error logger for route handlers.  Extracts the request ID from the
// action context so every error log is correlated with its request lifecycle.
const logRouteError = (req, eventName, err, extra = {}) => {
    const context = getActionContext(req);
    emitLog("error", eventName, {
        rid: shortRequestId(context.requestId),
        action: context.actionName,
        errorCode: err?.code || null,
        errorMessage: err?.message || String(err),
        stack: err?.stack || null,
        ...extra,
    });
};

// Structured informational step logger for route handlers (auth checks, DB ops, etc.).
const logRouteStep = (req, eventName, data = {}) => {
    const context = getActionContext(req);
    emitLog("info", eventName, {
        rid: shortRequestId(context.requestId),
        action: context.actionName,
        ...data,
    });
};

console.error = (...args) => writeLogWithSeparator(rawError, `[ERROR ${formatBgTime()}]`, ...args);
console.warn = (...args) => writeLogWithSeparator(rawWarn, `[WARN ${formatBgTime()}]`, ...args);
console.info = (...args) => writeLogWithSeparator(rawInfo, `[INFO ${formatBgTime()}]`, ...args);

app.use((req, res, next) => {
    const context = getActionContext(req);
    res.setHeader("X-Request-Id", context.requestId);

    const captureResponse = (body) => {
        context.responseCaptured = true;
        context.responseBody = body;
    };

    const originalSend = res.send.bind(res);
    const originalJson = res.json.bind(res);
    res.send = (body) => {
        captureResponse(body);
        return originalSend(body);
    };
    res.json = (body) => {
        captureResponse(body);
        return originalJson(body);
    };

    res.on("finish", () => {
        if (!context.startLogged) {
            logRequestStart(req, {
                note: "auto-start",
                includeBody: true,
                actionName: `${req.method} ${req.route?.path || req.path || req.originalUrl}`,
            });
        }
        logRequestEnd(req, res);
    });

    res.on("close", () => {
        if (context.endLogged || res.writableEnded) return;
        context.endLogged = true;
        emitLog("warn", "ACTION_ABORTED", {
            rid: shortRequestId(context.requestId),
            action: context.actionName,
            ms: Date.now() - context.receivedAtMs,
            status: res.statusCode,
        });
    });

    next();
});

const addStudentsToClass = async (classId, students) => {

    const facultyNumbers = students
        .map(s => {
            if (typeof s === "string" || typeof s === "number") {
                return String(s);
            }
            return s?.facultyNumber || s?.faculty_number;
        })
        .filter(Boolean)
        .map((value) => normalize(String(value)));


    if (facultyNumbers.length === 0) {
        return { assignedCount: 0, facultyNumbers: [] };
    }

    const normalizedToHash = new Map();
    for (const fac of facultyNumbers) {
        normalizedToHash.set(fac, hashForLookup(fac));
    }

    const hashes = Array.from(new Set(Array.from(normalizedToHash.values())));
    const placeholders = hashes.map((_, i) => `$${i + 1}`).join(",");

    const selectSql = `SELECT id, faculty_number_hash FROM students WHERE faculty_number_hash IN (${placeholders})`;

    const result = await pool.query(selectSql, hashes);

    const idMap = {};
    result.rows.forEach(row => {
        idMap[row.id] = row.faculty_number_hash;
    });

    const insertSql = "INSERT INTO class_students (class_id, student_id) VALUES ($1, $2) ON CONFLICT DO NOTHING";
    const studentIds = Object.keys(idMap);

    const client = await pool.connect();
    let addedCount = 0;
    try {
        await client.query("BEGIN");
        for (const id of studentIds) {
            const insertRes = await client.query(insertSql, [classId, id]);
            addedCount += insertRes.rowCount || 0;
        }
        await client.query("COMMIT");
    } catch (err) {
        await client.query("ROLLBACK");
        throw err;
    } finally {
        client.release();
    }

    return { assignedCount: addedCount, facultyNumbers };
};

// Central CORS configuration (explicit preflight + allowed headers)
const allowedOrigins = ["https://studentcheck-9ucp.onrender.com"]; // frontend origin(s)
app.use(cors({
    origin: (origin, callback) => {
        // Allow same-origin / server-to-server (no origin header) or listed origins
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    credentials: true,
    maxAge: 86400 // cache preflight for a day
}));

// Manual lightweight preflight handler (runs after cors sets headers)
app.use((req, res, next) => {
    if (req.method === "OPTIONS") {
        // Extra headers in case cors library missed something
        res.header("Access-Control-Allow-Origin", allowedOrigins[0]);
        res.header("Access-Control-Allow-Credentials", "true");
        res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
        res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        logRequestStart(req, { note: "Preflight -> 204", includeBody: false });
        return res.status(204).end();
    }
    next();
});

// connect to PostgreSQL
// DATABASE_URL must be the direct Supabase connection (port 5432), NOT the PgBouncer
// pooler URL (port 6543). PgBouncer's transaction mode does not support the DDL
// statements (ALTER TABLE, CREATE INDEX …) that run during server startup.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
    // Fail fast on connection attempts so startup errors surface immediately rather
    // than after the default 30 s socket hang.
    connectionTimeoutMillis: 10000,
    // Release idle clients after 30 s to avoid stale sockets toward the DB.
    idleTimeoutMillis: 30000,
    // Cap the pool size; Render free-tier Postgres limits concurrent connections.
    max: 10,
});

const db = createDbAdapter(pool);
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "");
const stripeService = createStripeService({
    stripe,
    db,
    appUrl: process.env.APP_URL || ""
});

// Stripe webhook must use raw body for signature verification
app.post("/api/billing/webhook", express.raw({ type: "application/json" }), createBillingWebhookHandler(stripeService));

// Lightweight uptime probe endpoint for frontend keep-alive pings.
app.get("/healthz", (req, res) => {
    res.set("Cache-Control", "no-store");
    return res.status(200).send({
        ok: true,
        service: "studentcheck-server",
        timestamp: new Date().toISOString(),
    });
});

app.use((req, res, next) => {
    const isJsonWrite = ["POST", "PUT", "PATCH"].includes(req.method);
    const isStripeWebhook = req.path === "/api/billing/webhook";
    if (!isJsonWrite || isStripeWebhook) return next();
    if (!req.is("application/json")) {
        return res.status(415).send({ error: "Content-Type must be application/json" });
    }
    next();
});

app.use(express.json({ limit: "32kb" }));
app.use("/api/billing", createBillingRouter(stripeService));

const createRouteRateLimiter = ({ windowMs, maxRequests }) => {
    const hits = new Map();
    return (req, res, next) => {
        const now = Date.now();
        const key = `${req.ip}:${req.path}`;
        const entry = hits.get(key);

        if (!entry || now - entry.windowStart >= windowMs) {
            hits.set(key, { count: 1, windowStart: now });
            return next();
        }

        entry.count += 1;
        if (entry.count > maxRequests) {
            return res.status(429).send({ error: "Too many requests" });
        }
        return next();
    };
};

const registrationRateLimit = createRouteRateLimiter({ windowMs: 10 * 60 * 1000, maxRequests: 20 });
const checkRouteRateLimit = createRouteRateLimiter({ windowMs: 10 * 60 * 1000, maxRequests: 60 });
const checkEmailHandler = buildCheckEmailHandler({ pool, normalize, hashForLookup, minimumDurationMs: 120 });
const checkFacultyNumberHandler = buildCheckFacultyNumberHandler({ pool, normalize, hashForLookup, minimumDurationMs: 120 });
const loginAttemptState = new Map();

const issueTeacherToken = ({ teacherId, emailHash, email }) => {
    const now = Math.floor(Date.now() / 1000);
    const expiresInSeconds = JWT_EXPIRES_IN_SECONDS;
    return {
        token: signAuthToken({
            secret: JWT_SECRET,
            payload: {
                sub: String(teacherId),
                teacherId: Number(teacherId),
                role: "teacher",
                email,
                emailHash,
                iss: JWT_ISSUER,
                aud: JWT_AUDIENCE,
                iat: now,
                exp: now + expiresInSeconds,
            },
        }),
        expiresIn: expiresInSeconds,
    };
};

const logAuthEvent = (details) => {
    emitLog("info", "AUTH_EVENT", details);
};

const requireTeacherAuth = async (req, res, next) => {
    const requestId = crypto.randomUUID();
    const parsed = parseAuthorizationHeader(req.headers.authorization);

    if (!parsed.ok) {
        logAuthEvent({
            requestId,
            endpoint: req.originalUrl,
            authHeaderPresent: Boolean(req.headers.authorization),
            tokenVerificationStatus: "rejected_header",
            statusCode: 401,
            reason: parsed.error,
        });
        return res.status(401).send({ error: parsed.error });
    }

    const verification = verifyAuthToken({
        token: parsed.token,
        secret: JWT_SECRET,
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
    });
    if (!verification.ok) {
        logAuthEvent({
            requestId,
            endpoint: req.originalUrl,
            authHeaderPresent: true,
            tokenVerificationStatus: "invalid_or_expired",
            verifyReason: verification.reason,
            statusCode: 401,
        });
        return res.status(401).send({ error: "Invalid or expired token" });
    }
    const payload = verification.payload;
    if (payload.role !== "teacher" || !payload.sub) {
        logAuthEvent({
            requestId,
            endpoint: req.originalUrl,
            authHeaderPresent: true,
            tokenVerificationStatus: "invalid_claims",
            statusCode: 401,
        });
        return res.status(401).send({ error: "Invalid or expired token" });
    }

    const teacherId = Number.parseInt(String(payload.sub), 10);
    if (!Number.isInteger(teacherId) || teacherId <= 0) {
        logAuthEvent({
            requestId,
            endpoint: req.originalUrl,
            authHeaderPresent: true,
            tokenVerificationStatus: "invalid_subject",
            statusCode: 401,
        });
        return res.status(401).send({ error: "Invalid or expired token" });
    }

    const teacherResult = await pool.query("SELECT id, email_hash FROM teachers WHERE id = $1", [teacherId]);
    if (!teacherResult.rows.length) {
        logAuthEvent({
            requestId,
            endpoint: req.originalUrl,
            authHeaderPresent: true,
            tokenVerificationStatus: "teacher_not_found",
            statusCode: 401,
            teacherId,
        });
        return res.status(401).send({ error: "Invalid or expired token" });
    }
    if (payload.emailHash && teacherResult.rows[0].email_hash && payload.emailHash !== teacherResult.rows[0].email_hash) {
        // Soft warning only: teacher identity is already validated by signed token + DB teacher id existence.
        logAuthEvent({
            requestId,
            endpoint: req.originalUrl,
            authHeaderPresent: true,
            tokenVerificationStatus: "email_hash_mismatch_soft",
            statusCode: 200,
            teacherId,
        });
    }

    req.authTeacherId = teacherId;
    req.authRequestId = requestId;
    req.user = {
        teacherId,
        role: "teacher",
        email: payload.email || null,
    };
    req.authTeacherEmailHash = teacherResult.rows[0].email_hash;
    logAuthEvent({
        requestId,
        endpoint: req.originalUrl,
        authHeaderPresent: true,
        tokenVerificationStatus: "ok",
        statusCode: 200,
        teacherId,
        teacherEmail: req.user.email,
    });
    next();
};

const getLoginAttemptKey = (req, identifier) => `${req.ip}|${req.path}|${String(identifier || "").slice(0, 256)}`;
const getRetryDelayMs = (fails) => Math.min(15000, fails * 750);

const enforceLoginThrottle = (req, res, key) => {
    const entry = loginAttemptState.get(key);
    const now = Date.now();
    if (entry && entry.lockedUntil && now < entry.lockedUntil) {
        return res.status(429).send({ error: "Too many attempts. Try again later." });
    }
    return null;
};

const recordLoginFailure = (key) => {
    const now = Date.now();
    const entry = loginAttemptState.get(key) || { fails: 0, lockedUntil: 0 };
    entry.fails += 1;
    entry.lastFailAt = now;
    entry.lockedUntil = now + getRetryDelayMs(entry.fails);
    loginAttemptState.set(key, entry);
};

const clearLoginFailures = (key) => {
    loginAttemptState.delete(key);
};

// Flag-controlled migration/backfill for encrypted/hash fields on sensitive columns
const APPLY_ENCRYPTION_MIGRATION =
    String(process.env.APPLY_ENCRYPTION_MIGRATION || "").toLowerCase() === "true";
const APPLY_ENCRYPTION_BACKFILL =
    String(process.env.APPLY_ENCRYPTION_BACKFILL || "").toLowerCase() === "true";

const applyEncryptionMigration = async (client) => {
    await client.query(`
        ALTER TABLE students
          ADD COLUMN IF NOT EXISTS email_encrypted TEXT,
          ADD COLUMN IF NOT EXISTS email_hash TEXT,
          ADD COLUMN IF NOT EXISTS faculty_number_encrypted TEXT,
          ADD COLUMN IF NOT EXISTS faculty_number_hash TEXT,
          ADD COLUMN IF NOT EXISTS password_hash TEXT,
          ADD COLUMN IF NOT EXISTS hash_algorithm TEXT,
          ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ;

        ALTER TABLE teachers
          ADD COLUMN IF NOT EXISTS email_encrypted TEXT,
          ADD COLUMN IF NOT EXISTS email_hash TEXT,
          ADD COLUMN IF NOT EXISTS password_hash TEXT,
          ADD COLUMN IF NOT EXISTS hash_algorithm TEXT,
          ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ;

        ALTER TABLE students ALTER COLUMN password DROP NOT NULL;
        ALTER TABLE teachers ALTER COLUMN password DROP NOT NULL;

        CREATE INDEX IF NOT EXISTS idx_students_email_hash ON students (email_hash);
        CREATE INDEX IF NOT EXISTS idx_students_faculty_number_hash ON students (faculty_number_hash);
        CREATE INDEX IF NOT EXISTS idx_teachers_email_hash ON teachers (email_hash);
        CREATE UNIQUE INDEX IF NOT EXISTS uq_students_email_hash ON students (email_hash) WHERE email_hash IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS uq_students_faculty_number_hash ON students (faculty_number_hash) WHERE faculty_number_hash IS NOT NULL;

        ALTER TABLE students DROP CONSTRAINT IF EXISTS students_group_check;
        ALTER TABLE students
            ADD CONSTRAINT students_group_check
            CHECK ("group" ~ '^[0-9]+$' AND "group"::integer BETWEEN 30 AND 50);
    `);
};

const applyAttendanceSchemaMigration = async (client) => {
    await client.query(`
        CREATE TABLE IF NOT EXISTS attendance_timestamps (
            id SERIAL PRIMARY KEY,
            class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
            student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            joined_at TIMESTAMPTZ,
            left_at TIMESTAMPTZ
        );

        ALTER TABLE attendances
            ADD COLUMN IF NOT EXISTS count INTEGER;
        UPDATE attendances
        SET count = 0
        WHERE count IS NULL;
        ALTER TABLE attendances
            ALTER COLUMN count SET DEFAULT 0;
        ALTER TABLE attendances
            ALTER COLUMN count SET NOT NULL;

        ALTER TABLE attendances
            ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
        UPDATE attendances
        SET updated_at = NOW()
        WHERE updated_at IS NULL;

        ALTER TABLE attendance_timestamps
            ADD COLUMN IF NOT EXISTS session_key TEXT,
            ADD COLUMN IF NOT EXISTS status TEXT,
            ADD COLUMN IF NOT EXISTS class_name TEXT,
            ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;

        UPDATE attendance_timestamps
        SET
            created_at = COALESCE(created_at, NOW()),
            updated_at = COALESCE(updated_at, NOW());

        UPDATE attendance_timestamps
        SET session_key = md5(
            COALESCE(class_id::text, '') || ':' ||
            COALESCE(student_id::text, '') || ':' ||
            COALESCE(joined_at::text, left_at::text, '')
        )
        WHERE session_key IS NULL;

        ALTER TABLE attendance_timestamps
            ALTER COLUMN created_at SET DEFAULT NOW();
        ALTER TABLE attendance_timestamps
            ALTER COLUMN created_at SET NOT NULL;
        ALTER TABLE attendance_timestamps
            ALTER COLUMN updated_at SET DEFAULT NOW();
        ALTER TABLE attendance_timestamps
            ALTER COLUMN updated_at SET NOT NULL;
        ALTER TABLE attendance_timestamps
            ALTER COLUMN session_key SET NOT NULL;

        CREATE INDEX IF NOT EXISTS idx_attendance_timestamps_class_student
            ON attendance_timestamps (class_id, student_id);
        CREATE INDEX IF NOT EXISTS idx_attendance_timestamps_class_student_session_key
            ON attendance_timestamps (class_id, student_id, session_key);
        CREATE INDEX IF NOT EXISTS idx_attendance_timestamps_class_joined_left
            ON attendance_timestamps (class_id, joined_at, left_at);
    `);
};

const getPlainTextFromPossiblyEncrypted = (value) => {
    const raw = String(value || "");
    if (!raw) return { plainText: "", wasEncrypted: false };

    try {
        return {
            plainText: decrypt(raw),
            wasEncrypted: true,
        };
    } catch {
        return {
            plainText: raw,
            wasEncrypted: false,
        };
    }
};

const backfillEncryptionForExistingData = async (client) => {

    const { rows: studentRows } = await client.query(`
        SELECT
            id,
            email,
            email_encrypted,
            email_hash,
            faculty_number,
            faculty_number_encrypted,
            faculty_number_hash
        FROM students
        WHERE email IS NOT NULL
           OR faculty_number IS NOT NULL
    `);

    let studentsUpdated = 0;
    for (const row of studentRows) {
        const updates = {};

        if (row.email) {
            const { plainText: emailPlain, wasEncrypted: emailWasEncrypted } =
                getPlainTextFromPossiblyEncrypted(row.email);
            const emailNorm = normalize(emailPlain);
            if (emailNorm && (!row.email_hash || !row.email_encrypted || !emailWasEncrypted)) {
                const emailEncrypted = encryptRaw(emailNorm);
                updates.email = emailEncrypted;
                updates.email_encrypted = emailEncrypted;
                updates.email_hash = hashForLookup(emailNorm);
            }
        }

        if (row.faculty_number) {
            const { plainText: facultyPlain } = getPlainTextFromPossiblyEncrypted(row.faculty_number);
            const facultyNorm = normalize(facultyPlain);
            if (facultyNorm && (!row.faculty_number_hash || !row.faculty_number_encrypted)) {
                updates.faculty_number_encrypted = encryptRaw(facultyNorm);
                updates.faculty_number_hash = hashForLookup(facultyNorm);
            }
        }

        const fields = Object.keys(updates);
        if (fields.length === 0) continue;

        const setFragments = fields.map((field, idx) => `${field} = $${idx + 1}`);
        const values = fields.map((field) => updates[field]);
        values.push(row.id);

        await client.query(
            `UPDATE students SET ${setFragments.join(", ")} WHERE id = $${fields.length + 1}`,
            values
        );
        studentsUpdated += 1;
    }

    const { rows: teacherRows } = await client.query(`
        SELECT
            id,
            email,
            email_encrypted,
            email_hash
        FROM teachers
        WHERE email IS NOT NULL
    `);

    let teachersUpdated = 0;
    for (const row of teacherRows) {
        const updates = {};

        if (row.email) {
            const { plainText: emailPlain, wasEncrypted: emailWasEncrypted } =
                getPlainTextFromPossiblyEncrypted(row.email);
            const emailNorm = normalize(emailPlain);
            if (emailNorm && (!row.email_hash || !row.email_encrypted || !emailWasEncrypted)) {
                const emailEncrypted = encryptRaw(emailNorm);
                updates.email = emailEncrypted;
                updates.email_encrypted = emailEncrypted;
                updates.email_hash = hashForLookup(emailNorm);
            }
        }

        const fields = Object.keys(updates);
        if (fields.length === 0) continue;

        const setFragments = fields.map((field, idx) => `${field} = $${idx + 1}`);
        const values = fields.map((field) => updates[field]);
        values.push(row.id);

        await client.query(
            `UPDATE teachers SET ${setFragments.join(", ")} WHERE id = $${fields.length + 1}`,
            values
        );
        teachersUpdated += 1;
    }

    return {
        studentRowsChecked: studentRows.length,
        studentsUpdated,
        teacherRowsChecked: teacherRows.length,
        teachersUpdated,
    };
};

const formatServerTime = (rawTime) => {
    const date = rawTime instanceof Date ? rawTime : new Date(rawTime);
    if (Number.isNaN(date.getTime())) {
        return String(rawTime);
    }
    return `${date.toISOString()} | Europe/Sofia: ${formatBgTime(date)}`;
};

const verifyAndPrintTables = async (client) => {
    const requiredTables = [
        "students",
        "teachers",
        "classes",
        "class_students",
        "attendances",
        "attendance_timestamps",
        "org_billing",
        "stripe_events",
    ];

    const { rows } = await client.query(`
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
        ORDER BY tablename ASC
    `);

    const existingTables = new Set(rows.map((row) => String(row.tablename)));
    emitLog("info", "DB_TABLES_DISCOVERED", {
        count: rows.length,
        tables: rows.map((row) => row.tablename),
    });

    const missingTables = requiredTables.filter((tableName) => !existingTables.has(tableName));
    for (const tableName of missingTables) {
        emitLog("warn", "DB_TABLE_MISSING", { table: tableName });
    }
};





(async () => {
    const DB_STARTUP_RETRIES = 3;
    const DB_STARTUP_RETRY_DELAY_MS = 3000;

    // Extract host from DATABASE_URL for diagnostic logging (never log the full URL).
    const resolvedDbHost = (() => {
        try {
            const u = new URL(process.env.DATABASE_URL || "");
            return `${u.hostname}:${u.port || 5432}`;
        } catch {
            return "(unparseable DATABASE_URL)";
        }
    })();

    emitLog("info", "DB_STARTUP_BEGIN", {
        dbHost: resolvedDbHost,
        applyEncryptionMigration: APPLY_ENCRYPTION_MIGRATION,
        applyEncryptionBackfill: APPLY_ENCRYPTION_BACKFILL,
    });

    for (let attempt = 1; attempt <= DB_STARTUP_RETRIES; attempt += 1) {
        let client;
        try {
            emitLog("info", "DB_CONNECT_ATTEMPT", { attempt, dbHost: resolvedDbHost });
            client = await pool.connect();
            emitLog("info", "DB_CONNECTED", { attempt, dbHost: resolvedDbHost });

            const result = await client.query("SELECT NOW() AS server_time");
            emitLog("info", "DB_SERVER_TIME", {
                serverTime: formatServerTime(result.rows[0]?.server_time),
            });

            // --- Ensure required tables exist (idempotent) ---
            await client.query(`
                CREATE TABLE IF NOT EXISTS classes (
                    id SERIAL PRIMARY KEY,
                    teacher_id INTEGER NOT NULL REFERENCES teachers(id) ON DELETE CASCADE,
                    name TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attendances (
                    id SERIAL PRIMARY KEY,
                    class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
                    student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                    updated_at TIMESTAMPTZ DEFAULT NOW(),
                    UNIQUE(class_id, student_id)
                );
            `);
            await applyAttendanceSchemaMigration(client);
            emitLog("info", "DB_ATTENDANCE_SCHEMA_READY", {});
            await db.ensureBillingTables();
            emitLog("info", "DB_BILLING_TABLES_READY", {});
            await verifyAndPrintTables(client);
            if (APPLY_ENCRYPTION_MIGRATION) {
                emitLog("info", "DB_ENCRYPTION_MIGRATION_START", {});
                await applyEncryptionMigration(client);
                emitLog("info", "DB_ENCRYPTION_MIGRATION_END", {});
            } else {
                emitLog("info", "DB_ENCRYPTION_MIGRATION_SKIPPED", {});
            }
            if (APPLY_ENCRYPTION_BACKFILL) {
                emitLog("info", "DB_ENCRYPTION_BACKFILL_START", {});
                const backfillSummary = await backfillEncryptionForExistingData(client);
                emitLog("info", "DB_ENCRYPTION_BACKFILL_END", backfillSummary);
            } else {
                emitLog("info", "DB_ENCRYPTION_BACKFILL_SKIPPED", {});
            }
            emitLog("info", "DB_STARTUP_END", {});
            break; // success — exit retry loop
        } catch (err) {
            const isTimeout = err.code === "ETIMEDOUT" || err.message?.includes("timeout") || err instanceof AggregateError;
            emitLog("error", "DB_STARTUP_ERROR", {
                attempt,
                dbHost: resolvedDbHost,
                errorCode: err.code || null,
                errorName: err.name || null,
                errorMessage: err.message || String(err),
                isTimeout,
                willRetry: attempt < DB_STARTUP_RETRIES,
            });
            if (attempt < DB_STARTUP_RETRIES) {
                emitLog("info", "DB_STARTUP_RETRY_WAIT", { delayMs: DB_STARTUP_RETRY_DELAY_MS, nextAttempt: attempt + 1 });
                await new Promise((resolve) => setTimeout(resolve, DB_STARTUP_RETRY_DELAY_MS));
            } else {
                emitLog("error", "DB_STARTUP_FAILED", {
                    dbHost: resolvedDbHost,
                    hint: "Verify DATABASE_URL points to the direct Supabase connection (port 5432), not the PgBouncer pooler (port 6543).",
                });
            }
        } finally {
            if (client) {
                client.release();
            }
        }
    }
})();

const tryDecryptValue = (value) => {
    if (typeof value !== "string" || !value) return null;
    try {
        return decrypt(value);
    } catch {
        return null;
    }
};

const identifierMatches = ({ inputNormalized, rowHash, rowPlain, rowEncrypted }) => {
    if (!inputNormalized) return false;

    if (rowHash && hashForLookup(inputNormalized) === rowHash) return true;

    if (typeof rowPlain === "string" && rowPlain && normalize(rowPlain) === inputNormalized) {
        return true;
    }

    const decryptedPlain = tryDecryptValue(rowPlain);
    if (decryptedPlain && normalize(decryptedPlain) === inputNormalized) {
        return true;
    }

    const decryptedEncrypted = tryDecryptValue(rowEncrypted);
    if (decryptedEncrypted && normalize(decryptedEncrypted) === inputNormalized) {
        return true;
    }

    return false;
};

const getResolvedEmailForResponse = (row) => {
    const fromMainColumn = resolveEmailForApi(row?.email);
    if (fromMainColumn) return fromMainColumn;

    const fromEncryptedColumn = resolveEmailForApi(row?.email_encrypted);
    if (fromEncryptedColumn) return fromEncryptedColumn;

    return null;
};

const canonicalizeFacultyNumberForResponse = (value) => {
    if (value === undefined || value === null) return null;
    const trimmed = String(value).trim();
    if (!trimmed) return null;
    return trimmed.toUpperCase();
};

const parsePositiveInteger = (value) => {
    const parsed = Number.parseInt(String(value), 10);
    if (!Number.isInteger(parsed) || parsed <= 0) return null;
    return parsed;
};

const getResolvedFacultyNumberForResponse = (row = {}) => {
    const fromEncryptedColumn = tryDecryptValue(row.faculty_number_encrypted);
    if (fromEncryptedColumn) return canonicalizeFacultyNumberForResponse(fromEncryptedColumn);

    const fromMainColumn = tryDecryptValue(row.faculty_number);
    if (fromMainColumn) return canonicalizeFacultyNumberForResponse(fromMainColumn);

    return canonicalizeFacultyNumberForResponse(row.faculty_number);
};

const emailResolveNullCountsByEndpoint = new Map();

const withStudentResponseIdentifiers = (row = {}, { endpoint = "unknown" } = {}) => {
    const response = serializeStudent(row);
    const sourceEmail = row.email ?? row.email_encrypted;

    if (typeof sourceEmail === "string" && sourceEmail.trim() && response.email === null) {
        const currentCount = emailResolveNullCountsByEndpoint.get(endpoint) || 0;
        const nextCount = currentCount + 1;
        emailResolveNullCountsByEndpoint.set(endpoint, nextCount);
        emitLog("warn", "EMAIL_RESOLVE_NULL", {
            endpoint,
            count: nextCount,
            student_id: response.student_id ?? null,
        });
    }

    return response;
};

const withAttendanceStudentIdentifiers = (row = {}) => {
    const response = { ...row };
    const studentId = parsePositiveInteger(row.student_id);
    const facultyNumber = getResolvedFacultyNumberForResponse(row);

    if (studentId) {
        response.student_id = studentId;
    }
    if (facultyNumber) {
        response.faculty_number = facultyNumber;
        response.facultyNumber = facultyNumber;
    }

    return response;
};

const ATTENDANCE_DERIVED_COUNT_FILTER_SQL = "(joined_at IS NOT NULL OR left_at IS NOT NULL)";
const ATTENDANCE_POSITIVE_STATUSES = new Set(["attended", "present", "completed", "checked_in", "checked-in"]);

const normalizeAttendanceStatus = (value) => {
    if (typeof value !== "string") return null;
    const trimmed = value.trim();
    if (!trimmed) return null;
    return trimmed.toLowerCase();
};

const isPositiveAttendanceStatus = (status) => {
    const normalized = normalizeAttendanceStatus(status);
    if (!normalized) return false;
    return ATTENDANCE_POSITIVE_STATUSES.has(normalized);
};

const parseOptionalIsoTimestamp = (value) => {
    if (value === undefined || value === null) {
        return { ok: true, value: null };
    }

    const text = String(value).trim();
    if (!text) {
        return { ok: true, value: null };
    }

    const parsed = new Date(text);
    if (Number.isNaN(parsed.getTime())) {
        return { ok: false, value: null };
    }

    return { ok: true, value: parsed.toISOString() };
};

const buildAttendanceSessionKey = ({ classId, studentId, joinedAt, leftAt }) => {
    const sessionWindowAnchor = joinedAt || leftAt || "";
    const raw = `${classId}|${studentId}|${sessionWindowAnchor}`;
    return crypto.createHash("sha256").update(raw).digest("hex");
};

const buildAttendanceStudentResolver = (client) => {
    const studentByIdCache = new Map();
    const studentByFacultyNormCache = new Map();
    let fallbackFacultyCandidates = null;

    const resolveById = async (value) => {
        const studentId = parsePositiveInteger(value);
        if (!studentId) return null;
        if (studentByIdCache.has(studentId)) {
            return studentByIdCache.get(studentId);
        }

        const { rows } = await client.query(
            `
            SELECT id, faculty_number, faculty_number_encrypted, faculty_number_hash
            FROM students
            WHERE id = $1
            LIMIT 1
            `,
            [studentId]
        );
        const row = rows[0] || null;
        studentByIdCache.set(studentId, row);
        return row;
    };

    const resolveByFacultyNumber = async (value) => {
        if (value === undefined || value === null) return null;
        const facultyNorm = normalize(String(value));
        if (!facultyNorm) return null;

        if (studentByFacultyNormCache.has(facultyNorm)) {
            return studentByFacultyNormCache.get(facultyNorm);
        }

        const facultyHash = hashForLookup(facultyNorm);
        const fastResult = await client.query(
            `
            SELECT id, faculty_number, faculty_number_encrypted, faculty_number_hash
            FROM students
            WHERE faculty_number_hash = $1
            LIMIT 1
            `,
            [facultyHash]
        );

        let row = fastResult.rows[0] || null;
        if (!row) {
            if (!fallbackFacultyCandidates) {
                const fallbackResult = await client.query(
                    `
                    SELECT id, faculty_number, faculty_number_encrypted, faculty_number_hash
                    FROM students
                    ORDER BY id ASC
                    LIMIT 10000
                    `
                );
                fallbackFacultyCandidates = fallbackResult.rows;
            }

            row = fallbackFacultyCandidates.find((candidate) => {
                return identifierMatches({
                    inputNormalized: facultyNorm,
                    rowHash: candidate.faculty_number_hash,
                    rowPlain: candidate.faculty_number,
                    rowEncrypted: candidate.faculty_number_encrypted,
                });
            }) || null;
        }

        studentByFacultyNormCache.set(facultyNorm, row);
        if (row?.id) {
            studentByIdCache.set(Number(row.id), row);
        }
        return row;
    };

    return {
        resolveById,
        resolveByFacultyNumber,
    };
};

const recomputeAttendanceSummaryForClass = async (client, classId) => {
    const classIdNum = parsePositiveInteger(classId);
    if (!classIdNum) {
        throw new Error("Invalid class_id for summary recomputation");
    }

    await client.query(
        `
        WITH derived AS (
            SELECT
                class_id,
                student_id,
                COUNT(DISTINCT session_key)::INTEGER AS derived_count
            FROM attendance_timestamps
            WHERE class_id = $1
              AND ${ATTENDANCE_DERIVED_COUNT_FILTER_SQL}
            GROUP BY class_id, student_id
        )
        INSERT INTO attendances (class_id, student_id, count, updated_at)
        SELECT
            d.class_id,
            d.student_id,
            d.derived_count,
            NOW()
        FROM derived d
        ON CONFLICT (class_id, student_id)
        DO UPDATE SET
            count = EXCLUDED.count,
            updated_at = NOW()
        `,
        [classIdNum]
    );

    await client.query(
        `
        UPDATE attendances a
        SET
            count = 0,
            updated_at = NOW()
        WHERE a.class_id = $1
          AND NOT EXISTS (
              SELECT 1
              FROM attendance_timestamps at
              WHERE at.class_id = a.class_id
                AND at.student_id = a.student_id
                AND ${ATTENDANCE_DERIVED_COUNT_FILTER_SQL}
          )
          AND COALESCE(a.count, 0) <> 0
        `,
        [classIdNum]
    );
};

const updateAuthFieldsById = async (tableName, id, updates) => {
    const fields = Object.keys(updates || {});
    if (fields.length === 0) return;

    const setSql = fields.map((field, idx) => `${field} = $${idx + 1}`).join(", ");
    const values = fields.map((field) => updates[field]);
    values.push(id);

    await pool.query(
        `UPDATE ${tableName} SET ${setSql} WHERE id = $${fields.length + 1}`,
        values
    );
};







app.post("/teacherLogin", async (req, res) => {
    logRequestStart(req);

    try {
        const { email, password } = req.body;
        const loginAttemptKey = getLoginAttemptKey(req, normalize(email || ""));
        const throttleResponse = enforceLoginThrottle(req, res, loginAttemptKey);
        if (throttleResponse) return throttleResponse;

        if (!email || !password) {
            recordLoginFailure(loginAttemptKey);
            return res.status(401).send({
                error: "Invalid credentials"
            });
        }


        const emailNorm = normalize(email);
        const emailHash = hashForLookup(emailNorm);

        const fastResult = await pool.query(
            `
            SELECT id, full_name, email, email_encrypted, email_hash, password, password_hash, hash_algorithm, password_updated_at
            FROM teachers
            WHERE email_hash = $1
            LIMIT 1
            `,
            [emailHash]
        );

        let candidateRows = fastResult.rows;
        if (!candidateRows.length) {
            const fallbackCandidates = await pool.query(
                `
                SELECT id, full_name, email, email_encrypted, email_hash, password, password_hash, hash_algorithm, password_updated_at
                FROM teachers
                ORDER BY id ASC
                LIMIT 5000
                `
            );

            candidateRows = fallbackCandidates.rows.filter((row) => {
                return identifierMatches({
                    inputNormalized: emailNorm,
                    rowHash: row.email_hash,
                    rowPlain: row.email,
                    rowEncrypted: row.email_encrypted,
                });
            });
        }

        let teacher = null;
        let passwordCheck = { isValid: false, needsMigration: false, matchedWith: null };
        for (const candidate of candidateRows) {
            const candidateCheck = await verifyPasswordWithMigration({
                inputPassword: password,
                rowPassword: candidate.password,
                rowPasswordHash: candidate.password_hash,
                rowHashAlgorithm: candidate.hash_algorithm,
                legacyHashVerifier: hashExactForLookup,
                legacyDecryptor: tryDecryptValue,
            });

            if (candidateCheck.isValid) {
                teacher = candidate;
                passwordCheck = candidateCheck;
                break;
            }
        }

        if (!teacher || !passwordCheck.isValid) {
            recordLoginFailure(loginAttemptKey);
            return res.status(401).send({
                error: "Invalid credentials"
            });
        }
        clearLoginFailures(loginAttemptKey);

        const updates = {};
        const emailFromMainColumn = tryDecryptValue(teacher.email);

        if (!teacher.email_hash) {
            updates.email_hash = emailHash;
        }
        if (!teacher.email_encrypted) {
            updates.email_encrypted = emailFromMainColumn ? teacher.email : encryptRaw(emailNorm);
        }
        if (!emailFromMainColumn) {
            updates.email = updates.email_encrypted || encryptRaw(emailNorm);
        }

        if (passwordCheck.needsMigration) {
            Object.assign(updates, await buildArgon2PasswordFields(password));
        } else {
            if (!teacher.hash_algorithm) {
                updates.hash_algorithm = ARGON2_ALGORITHM;
            }
            if (!teacher.password_updated_at) {
                updates.password_updated_at = new Date();
            }
            if (teacher.password !== null) {
                updates.password = null;
            }
        }

        await updateAuthFieldsById("teachers", teacher.id, updates);
        const resolvedEmail = getResolvedEmailForResponse({
            ...teacher,
            ...updates,
        });
        const tokenPayload = issueTeacherToken({
            teacherId: teacher.id,
            emailHash: emailHash,
            email: normalize(resolvedEmail || emailNorm),
        });

        return res.send({
            message: "Teacher login successful",
            teacher: {
                email: resolvedEmail,
                fullName: teacher.full_name
            },
            token: tokenPayload.token,
            accessToken: tokenPayload.token,
            expiresIn: tokenPayload.expiresIn,
            loginSuccess: true
        });
    } catch (error) {
        logRouteError(req, "TEACHER_LOGIN_ERROR", error);
        return res.status(500).send({
            error: "Internal server error"
        });
    }
});





app.post("/studentLogin", async (req, res) => {
    logRequestStart(req);

    try {
        const { facultyNumber, password } = req.body;
        const loginAttemptKey = getLoginAttemptKey(req, normalize(facultyNumber || ""));
        const throttleResponse = enforceLoginThrottle(req, res, loginAttemptKey);
        if (throttleResponse) return throttleResponse;

        if (!facultyNumber || !password) {
            recordLoginFailure(loginAttemptKey);
            return res.status(401).send({
                error: "Invalid credentials"
            });
        }


        const facultyNorm = normalize(facultyNumber);
        const facultyHash = hashForLookup(facultyNorm);

        const fastResult = await pool.query(
            `
            SELECT
                id,
                full_name,
                email,
                email_encrypted,
                email_hash,
                faculty_number,
                faculty_number_encrypted,
                faculty_number_hash,
                password,
                password_hash,
                hash_algorithm,
                password_updated_at,
                "group",
                course,
                faculty,
                level,
                specialization
            FROM students
            WHERE faculty_number_hash = $1
            LIMIT 1
            `,
            [facultyHash]
        );

        let candidateRows = fastResult.rows;
        if (!candidateRows.length) {
            const fallbackCandidates = await pool.query(
                `
                SELECT
                    id,
                    full_name,
                    email,
                    email_encrypted,
                    email_hash,
                    faculty_number,
                    faculty_number_encrypted,
                    faculty_number_hash,
                    password,
                    password_hash,
                    hash_algorithm,
                    password_updated_at,
                    "group",
                    course,
                    faculty,
                    level,
                    specialization
                FROM students
                ORDER BY id ASC
                LIMIT 10000
                `
            );

            candidateRows = fallbackCandidates.rows.filter((row) => {
                return identifierMatches({
                    inputNormalized: facultyNorm,
                    rowHash: row.faculty_number_hash,
                    rowPlain: row.faculty_number,
                    rowEncrypted: row.faculty_number_encrypted,
                });
            });
        }

        let studentRow = null;
        let passwordCheck = { isValid: false, needsMigration: false, matchedWith: null };
        for (const candidate of candidateRows) {
            const candidateCheck = await verifyPasswordWithMigration({
                inputPassword: password,
                rowPassword: candidate.password,
                rowPasswordHash: candidate.password_hash,
                rowHashAlgorithm: candidate.hash_algorithm,
                legacyHashVerifier: hashExactForLookup,
                legacyDecryptor: tryDecryptValue,
            });

            if (candidateCheck.isValid) {
                studentRow = candidate;
                passwordCheck = candidateCheck;
                break;
            }
        }

        if (!studentRow || !passwordCheck.isValid) {
            recordLoginFailure(loginAttemptKey);
            return res.status(401).send({
                error: "Invalid credentials"
            });
        }
        clearLoginFailures(loginAttemptKey);

        const updates = {};
        const emailFromMainColumn = tryDecryptValue(studentRow.email);
        const facultyFromMainColumn = tryDecryptValue(studentRow.faculty_number);

        if (passwordCheck.needsMigration) {
            Object.assign(updates, await buildArgon2PasswordFields(password));
        } else {
            if (!studentRow.hash_algorithm) {
                updates.hash_algorithm = ARGON2_ALGORITHM;
            }
            if (!studentRow.password_updated_at) {
                updates.password_updated_at = new Date();
            }
            if (studentRow.password !== null) {
                updates.password = null;
            }
        }

        if (!studentRow.faculty_number_hash) {
            updates.faculty_number_hash = facultyHash;
        }
        if (!studentRow.faculty_number_encrypted) {
            updates.faculty_number_encrypted = facultyFromMainColumn
                ? studentRow.faculty_number
                : encryptRaw(facultyNorm);
        }

        if (!studentRow.email_hash || !studentRow.email_encrypted || !emailFromMainColumn) {
            const resolvedEmail = getResolvedEmailForResponse(studentRow);
            const normalizedEmail = normalize(resolvedEmail || "");
            if (normalizedEmail) {
                if (!studentRow.email_hash) {
                    updates.email_hash = hashForLookup(normalizedEmail);
                }
                if (!studentRow.email_encrypted) {
                    updates.email_encrypted = emailFromMainColumn
                        ? studentRow.email
                        : encryptRaw(normalizedEmail);
                }
                if (!emailFromMainColumn) {
                    updates.email = updates.email_encrypted || encryptRaw(normalizedEmail);
                }
            }
        }

        await updateAuthFieldsById("students", studentRow.id, updates);

        const student = withStudentResponseIdentifiers({
            ...studentRow,
            ...updates,
        }, { endpoint: "POST /studentLogin" });

        return res.send({
            message: "Student login successful",
            student,
            loginSuccess: true
        });
    } catch (error) {
        logRouteError(req, "STUDENT_LOGIN_ERROR", error);
        return res.status(500).send({
            error: "Internal server error"
        });
    }
});





app.post("/students/check-email", checkRouteRateLimit, async (req, res) => {
    logRequestStart(req, { includeBody: false });
    return checkEmailHandler(req, res);
});

app.post("/students/check-faculty-number", checkRouteRateLimit, async (req, res) => {
    logRequestStart(req, { includeBody: false });
    return checkFacultyNumberHandler(req, res);
});

app.post("/registration", registrationRateLimit, async (req, res) => {
    logRequestStart(req);
    const requestId = crypto.randomUUID();

    try {
        const user = req.body;
        const fullName = `${user.firstName} ${user.middleName || ''} ${user.lastName}`.replace(/\s+/g, ' ').trim();

        const courseValue = user.course;
        const groupValue = user.group;
        const validCourses = ["1", "2", "3", "4"];
        const groupValidation = parseAndValidateGroup(groupValue);

        if (courseValue === undefined || courseValue === null || !validCourses.includes(String(courseValue))) {
            return res.status(400).send({ message: "Invalid course. Must be 1–4." });
        }
        if (!groupValidation.isValid) {
            return res.status(400).send({ message: "Invalid group. Must be 30-50." });
        }

        if (!user.email || !user.facultyNumber || !user.password) {
            return res.status(400).send({
                message: "Email, faculty number and password are required."
            });
        }

        const normalizedEmail = normalizeEmailInput(user.email, normalize);
        const normalizedFacultyNumber = normalizeFacultyNumberInput(user.facultyNumber, normalize);
        if (!isValidEmail(normalizedEmail) || !isValidFacultyNumber(normalizedFacultyNumber)) {
            return res.status(400).send({ message: "Invalid registration data." });
        }

        const emailEncrypted = encryptRaw(normalizedEmail);
        const emailHash = hashForLookup(normalizedEmail);

        const facultyEncrypted = encryptRaw(normalizedFacultyNumber);
        const facultyHash = hashForLookup(normalizedFacultyNumber);

        const passwordFields = await buildArgon2PasswordFields(user.password);

        const duplicateCheck = await pool.query(
            `
            SELECT
                EXISTS(SELECT 1 FROM students WHERE email_hash = $1) AS email_exists,
                EXISTS(SELECT 1 FROM students WHERE faculty_number_hash = $2) AS faculty_number_exists
            `,
            [emailHash, facultyHash]
        );
        const conflicts = {
            email: Boolean(duplicateCheck.rows[0]?.email_exists),
            facultyNumber: Boolean(duplicateCheck.rows[0]?.faculty_number_exists),
        };
        if (conflicts.email || conflicts.facultyNumber) {
            return res.status(409).send({
                error: "Registration failed. Please use a different email or faculty number.",
                conflicts,
                registrationSuccess: false
            });
        }

        const insertSql = `
            INSERT INTO students (
                full_name,
                email,
                faculty_number,
                password,
                password_hash,
                hash_algorithm,
                password_updated_at,
                level,
                faculty,
                specialization,
                "group",
                course,
                created,
                email_encrypted,
                email_hash,
                faculty_number_encrypted,
                faculty_number_hash
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17
            )
            RETURNING id, full_name, email, faculty_number, "group", course, faculty, level, specialization
        `;
        const insertValues = [
            fullName,
            emailEncrypted,
            facultyEncrypted,
            passwordFields.password,
            passwordFields.password_hash,
            passwordFields.hash_algorithm,
            passwordFields.password_updated_at,
            user.level,
            user.faculty,
            user.specialization,
            String(groupValidation.parsed),
            String(courseValue),
            new Date(),
            emailEncrypted,
            emailHash,
            facultyEncrypted,
            facultyHash,
        ];
        const result = await insertStudentWithIdCollisionRecovery({
            pool,
            insertSql,
            insertValues,
            requestId,
            logger: console,
        });

        const student = withStudentResponseIdentifiers({
            ...result.rows[0],
            email: normalizedEmail,
            email_encrypted: result.rows[0].email,
            faculty_number: normalizedFacultyNumber,
        }, { endpoint: "POST /registration" });
        return res.send({ message: "User registration successful", student, registrationSuccess: true });
    } catch (error) {
        const mapped = mapRegistrationUniqueViolation(error);
        if (mapped && mapped.type === "duplicate_email") {
            logRouteStep(req, "REGISTRATION_DUPLICATE_EMAIL", { requestId, constraint: mapped.constraint });
            return res.status(409).send({
                error: "Registration failed. Please use a different email or faculty number.",
                conflicts: { email: true, facultyNumber: false },
                registrationSuccess: false
            });
        }
        if (mapped && mapped.type === "duplicate_faculty_number") {
            logRouteStep(req, "REGISTRATION_DUPLICATE_FACULTY", { requestId, constraint: mapped.constraint });
            return res.status(409).send({
                error: "Registration failed. Please use a different email or faculty number.",
                conflicts: { email: false, facultyNumber: true },
                registrationSuccess: false
            });
        }
        if (mapped && mapped.type === "id_collision") {
            logRouteError(req, "REGISTRATION_ID_COLLISION_UNRECOVERED", error, {
                requestId,
                constraint: mapped.constraint,
                retryFailed: Boolean(error.registrationRetryFailed),
            });
            return res.status(500).send({ error: "Internal server error", registrationSuccess: false });
        }
        // Unique violation (email or other unique columns)
        if (error && error.code === "23505") {
            logRouteStep(req, "REGISTRATION_DUPLICATE_UNIQUE_VIOLATION", { requestId, constraint: error.constraint, detail: error.detail });
            return res.status(409).send({
                error: "Registration failed. Please use a different email or faculty number.",
                registrationSuccess: false
            });
        }
        logRouteError(req, "REGISTRATION_ERROR", error, { requestId });
        return res.status(500).send({ error: "Internal server error", registrationSuccess: false });
    }
});








app.get("/students", async (req, res) => {
    logRequestStart(req);

    const {
        level,
        faculty,
        specialization,
        group,
        search
    } = req.query || {};

    try {
        const whereClauses = [];
        const params = [];

        const addFilter = (column, value) => {
            params.push(String(value).toLowerCase());
            whereClauses.push(`LOWER(${column}) = $${params.length}`);
        };

        if (level) addFilter("level", level);
        if (faculty) addFilter("faculty", faculty);
        if (specialization) addFilter("specialization", specialization);
        if (group) addFilter("\"group\"", group);

        if (search) {
            const term = `%${String(search).toLowerCase()}%`;
            params.push(term);
            const placeholder = `$${params.length}`;
            whereClauses.push(
                `(LOWER(full_name) LIKE ${placeholder} OR LOWER(faculty_number) LIKE ${placeholder})`
            );
        }

        const whereSql = whereClauses.length ? `WHERE ${whereClauses.join(" AND ")}` : "";
        const sql = `SELECT * FROM students ${whereSql} ORDER BY id DESC`;

        const result = await pool.query(sql, params);
        const students = result.rows.map((row) => withStudentResponseIdentifiers(row, { endpoint: "GET /students" }));
        return res.send({ students });
    } catch (error) {
        logRouteError(req, "STUDENTS_FETCH_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});


// ----------------- Class Creation Endpoint -----------------
// Expects body: { name: string, students?: Array }
app.post("/classes", requireTeacherAuth, async (req, res) => {
    logRequestStart(req);

    const { name, students } = req.body || {};

    if (!name) {
        return res.status(400).send({ error: "Class name is required" });
    }
    try {
        const teacherId = req.authTeacherId;


        const insertResult = await pool.query(
            "INSERT INTO classes (teacher_id, name) VALUES ($1, $2) RETURNING id, teacher_id, name",
            [teacherId, name]
        );

        const created = insertResult.rows[0];

        if (Array.isArray(students) && students.length > 0) {
            await addStudentsToClass(created.id, students);
        }

        res.status(201).send({ message: "Class created", class: created });

    } catch (error) {
        logRouteError(req, "CLASS_CREATE_ERROR", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// (Optional helper) List classes for a teacher by email query param: /classes?teacherEmail=...
app.get("/classes", async (req, res) => {
    logRequestStart(req);
    const { teacherEmail, class_id } = req.query;
    try {
        const requestedClassIdRaw = class_id;
        if (requestedClassIdRaw !== undefined) {
            const requestedClassId = Number.parseInt(String(requestedClassIdRaw), 10);
            if (!Number.isInteger(requestedClassId) || requestedClassId <= 0) {
                return res.status(400).send({ error: "class_id must be a positive integer" });
            }

            const classResult = await pool.query(
                `
                SELECT
                    id,
                    teacher_id,
                    name,
                    COALESCE(completed_classes_count, 0) AS completed_classes_count
                FROM classes
                WHERE id = $1
                `,
                [requestedClassId]
            );
            if (classResult.rows.length === 0) {
                return res.status(404).send({ error: "Class not found" });
            }

            const row = classResult.rows[0];
            return res.send({
                message: "Class fetched",
                class: row,
                classes: [row],
            });
        }

        if (teacherEmail) {
            const teacherEmailNorm = normalize(teacherEmail);
            const teacherEmailHash = hashForLookup(teacherEmailNorm);
            const t = await pool.query("SELECT id FROM teachers WHERE email_hash = $1", [teacherEmailHash]);
            if (t.rows.length === 0) {
                return res.status(404).send({ error: "Teacher not found" });
            }
            const teacherId = t.rows[0].id;

            const classes = await pool.query(
                `
                SELECT
                    id,
                    teacher_id,
                    name,
                    COALESCE(completed_classes_count, 0) AS completed_classes_count
                FROM classes
                WHERE teacher_id = $1
                ORDER BY id DESC
                `,
                [teacherId]
            );
            
            return res.send({ message: "Classes fetched", classes: classes.rows });
        } else {
            const classes = await pool.query(
                `
                SELECT
                    id,
                    teacher_id,
                    name,
                    COALESCE(completed_classes_count, 0) AS completed_classes_count
                FROM classes
                ORDER BY id DESC
                `
            );
            return res.send({ message: "All classes fetched", classes: classes.rows });
        }
    } catch (error) {
        logRouteError(req, "CLASSES_FETCH_ERROR", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Class Rename Endpoint -----------------
// Expects body: { classId: number, name: string }
app.put("/classes", requireTeacherAuth, async (req, res) => {
    logRequestStart(req);

    const { classId, name } = req.body || {};

    if (!classId) {
        return res.status(400).send({ error: "classId is required" });
    }
    if (!name) {
        return res.status(400).send({ error: "name is required" });
    }
    try {
        const teacherId = req.authTeacherId;

        const classResult = await pool.query(
            "SELECT id, teacher_id FROM classes WHERE id = $1",
            [classId]
        );
        if (classResult.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }
        const classTeacherId = Number.parseInt(String(classResult.rows[0].teacher_id), 10);
        if (!Number.isInteger(classTeacherId) || classTeacherId !== teacherId) {
            return res.status(403).send({ error: "You do not have permission to rename this class" });
        }

        const updateResult = await pool.query(
            "UPDATE classes SET name = $1 WHERE id = $2 AND teacher_id = $3",
            [name, classId, teacherId]
        );

        if (updateResult.rowCount === 0) {
            return res.status(404).send({ error: "Class not found for this teacher" });
        }

        return res.status(200).send({ success: true });
    } catch (error) {
        logRouteError(req, "CLASS_RENAME_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Class Deletion Endpoint -----------------
// Expects body: { classId: number }
// Deletes class + related rows (class_students, attendances, attendance_timestamps)
app.delete("/classes", requireTeacherAuth, async (req, res) => {
    logRequestStart(req);

    const { classId } = req.body || {};

    if (!classId) {
        return res.status(400).send({ error: "classId is required" });
    }
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        const teacherId = req.authTeacherId;

        const classResult = await client.query(
            "SELECT id, teacher_id FROM classes WHERE id = $1",
            [classId]
        );
        if (classResult.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).send({ error: "Class not found" });
        }
        const classTeacherId = Number.parseInt(String(classResult.rows[0].teacher_id), 10);
        if (!Number.isInteger(classTeacherId) || classTeacherId !== teacherId) {
            await client.query("ROLLBACK");
            return res.status(403).send({ error: "You do not have permission to delete this class" });
        }

        await client.query("DELETE FROM class_students WHERE class_id = $1", [classId]);
        await client.query("DELETE FROM attendance_timestamps WHERE class_id = $1", [classId]);
        await client.query("DELETE FROM attendances WHERE class_id = $1", [classId]);

        const deleteClass = await client.query(
            "DELETE FROM classes WHERE id = $1 AND teacher_id = $2 RETURNING id",
            [classId, teacherId]
        );

        if (deleteClass.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).send({ error: "Class not found for this teacher" });
        }

        await client.query("COMMIT");
        return res.status(200).send({ success: true });
    } catch (error) {
        await client.query("ROLLBACK");
        logRouteError(req, "CLASS_DELETE_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    } finally {
        client.release();
    }
});



const postClassStudentsHandler = buildPostClassStudentsHandler({
    pool,
    normalize,
    hashForLookup,
    addStudentsToClass,
    logger: console,
});
app.post("/class_students", requireTeacherAuth, async (req, res) => {
    logRequestStart(req);
    return postClassStudentsHandler(req, res);
});






app.get("/class_students", async (req, res) => {
    logRequestStart(req);
    const classId = req.query.class_id;
    if (!classId) {
        return res.status(400).send({ error: "class_id query parameter is required" });
    }
    try {
        const { rows } = await pool.query(
            `
            SELECT
                s.id,
                s.id AS student_id,
                s.full_name,
                s.email,
                s.email_encrypted,
                s.faculty_number,
                s.faculty_number_encrypted,
                s."group",
                s.course,
                s.faculty,
                s.level,
                s.specialization
            FROM class_students cs
            JOIN students s ON s.id = cs.student_id
            WHERE cs.class_id = $1
            ORDER BY s.full_name ASC, s.id ASC
            `,
            [classId]
        );

        const students = rows.map((row) => withStudentResponseIdentifiers(row, { endpoint: "GET /class_students" }));
        return res.send({
            message: "Class students fetched",
            students
        });
    } catch (error) {
        logRouteError(req, "CLASS_STUDENTS_FETCH_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});





app.get("/get_student_classes", async (req, res) => {
    logRequestStart(req);

    const rawStudentId = req.query.student_id;

    if (!rawStudentId || rawStudentId === "undefined" || rawStudentId === "null") {
        return res.status(400).send({ error: "student_id query parameter is required" });
    }

    const studentId = Number(rawStudentId);
    if (!Number.isFinite(studentId) || studentId <= 0) {
        return res.status(400).send({ error: "student_id must be a valid number" });
    }

    const sql = `SELECT * FROM class_students WHERE student_id = $1`;
    const result  = await pool.query(sql, [studentId]);





    // Collect unique class IDs from result rows
    const classIds = Array.from(new Set(result.rows.map(row => Number(row.class_id)).filter(Boolean)));

    let classNames = [];

    if (classIds.length > 0) {
        const placeholders = classIds.map((_, i) => `$${i + 1}`).join(',');
        const sql = `SELECT id, name FROM classes WHERE id IN (${placeholders})`;
        const { rows: classRows } = await pool.query(sql, classIds);

        // Build id -> name map
        const nameById = new Map(classRows.map(row => [Number(row.id), row.name]));

        // Preserve original order if needed
        classNames = result.rows
            .map(row => nameById.get(Number(row.class_id)))
            .filter(Boolean);
    }






    return res.send({
        message: "Student classes fetched",
        class_names: classNames
    });

});





app.get("/get_class_id_by_name", async (req, res) => {
    logRequestStart(req);

    var className = req.query.class_name;

    const sql = `SELECT id FROM classes WHERE name = $1`;
    const result  = await pool.query(sql, [className]);


    if (result.rows.length === 0) {
        return res.status(404).send({ error: "Class not found" });
    }

    const class_id = result.rows[0].id;


    return res.send({
        message: "Class ID fetched",
        class_id: class_id
    });
});



// ----------------- Attendance Recording Endpoint -----------------
// Accepts body: { class_id, student_ids } or { class_id, student_id } or { class_id, faculty_number }
app.post("/attendance", async (req, res) => {
    logRequestStart(req);
    
    const { class_id, student_ids, student_id, faculty_number } = req.body || {};


    if (!class_id || (!student_ids && !student_id && !faculty_number)) {
        return res.status(400).send({ error: "class_id and student_id or faculty_number are required" });
    }

    try {
        const classIdNum = Number(class_id);
        if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
            return res.status(400).send({ error: "class_id must be a valid number" });
        }

        // Verify class exists
        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        if (classCheck.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        const upsertSql = `
            INSERT INTO attendances (class_id, student_id)
            VALUES ($1, $2)
            ON CONFLICT (class_id, student_id)
            DO UPDATE SET count = COALESCE(attendances.count, 0) + 1
            RETURNING id, class_id, student_id, count
        `;

        // Branch 1: array of student IDs
        if (Array.isArray(student_ids)) {
            const studentIdsInt = student_ids
                .map(value => Number(value))
                .filter(Number.isFinite);

            const uniqueIds = Array.from(new Set(studentIdsInt));

            if (uniqueIds.length === 0) {
                return res.status(400).send({ error: "No valid student_ids provided" });
            }

            const results = [];
            for (const sid of uniqueIds) {
                const { rows } = await pool.query(upsertSql, [classIdNum, sid]);
                results.push(rows[0]);
            }

            return res.status(200).send({ success: true, attendance: results });
        }

        // Branch 2: single student_id or faculty_number
        let resolvedStudentId = null;

        if (student_id !== undefined && student_id !== null) {
            const sid = Number(student_id);
            if (!Number.isFinite(sid) || sid <= 0) {
                return res.status(400).send({ error: "student_id must be a valid number" });
            }
            const studentCheck = await pool.query("SELECT id FROM students WHERE id = $1", [sid]);
            if (studentCheck.rows.length === 0) {
                return res.status(404).send({ error: "Student not found" });
            }
            resolvedStudentId = sid;
        } else if (faculty_number) {
            const facNorm = normalize(faculty_number);
            const facHash = hashForLookup(facNorm);
            const studentCheck = await pool.query(
                "SELECT id FROM students WHERE faculty_number_hash = $1",
                [facHash]
            );
            if (studentCheck.rows.length === 0) {
                return res.status(404).send({ error: "Student not found" });
            }
            resolvedStudentId = studentCheck.rows[0].id;
        }

        if (!resolvedStudentId) {
            return res.status(400).send({ error: "student_id or faculty_number is required" });
        }

        const { rows } = await pool.query(upsertSql, [classIdNum, resolvedStudentId]);
        return res.status(200).send({ success: true, attendance: rows[0] });
    } catch (error) {
        logRouteError(req, "ATTENDANCE_RECORD_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Transactional Attendance Finish Endpoint -----------------
// Accepts body:
// {
//   class_id: number,
//   class_name?: string,
//   records: [{ student_id?, faculty_number?, status?, joined_at?, left_at? }]
// }
app.post("/attendance/finish", async (req, res) => {
    logRequestStart(req);

    const { class_id, class_name, records } = req.body || {};
    const classIdNum = parsePositiveInteger(class_id);

    if (!classIdNum) {
        return res.status(400).send({ error: "class_id must be a valid positive integer" });
    }

    if (!Array.isArray(records) || records.length === 0) {
        return res.status(400).send({ error: "records must be a non-empty array" });
    }

    const classNameNormalized = typeof class_name === "string" ? class_name.trim() : null;
    if (class_name !== undefined && class_name !== null && !classNameNormalized) {
        return res.status(400).send({ error: "class_name must be a non-empty string when provided" });
    }

    const client = await pool.connect();
    let transactionOpen = false;

    try {
        await client.query("BEGIN");
        transactionOpen = true;

        // Serialize writes for this class to keep idempotency deterministic across retries.
        await client.query("SELECT pg_advisory_xact_lock($1::bigint)", [classIdNum]);

        const classCheck = await client.query(
            `
            SELECT id, name
            FROM classes
            WHERE id = $1
            LIMIT 1
            `,
            [classIdNum]
        );
        if (!classCheck.rows.length) {
            await client.query("ROLLBACK");
            transactionOpen = false;
            return res.status(404).send({ error: "Class not found" });
        }

        const persistedClassName = classNameNormalized || classCheck.rows[0].name || null;
        const studentResolver = buildAttendanceStudentResolver(client);

        const validationErrors = [];
        const conflictErrors = [];
        const candidateRecords = [];

        for (let index = 0; index < records.length; index += 1) {
            const record = records[index];
            if (!record || typeof record !== "object" || Array.isArray(record)) {
                validationErrors.push({
                    index,
                    field: "record",
                    message: "Each records[] entry must be an object",
                });
                continue;
            }

            const rawStudentId = record.student_id ?? record.studentId;
            const rawFacultyNumber = record.faculty_number ?? record.facultyNumber;
            if (
                (rawStudentId === undefined || rawStudentId === null || String(rawStudentId).trim() === "")
                && (rawFacultyNumber === undefined || rawFacultyNumber === null || String(rawFacultyNumber).trim() === "")
            ) {
                validationErrors.push({
                    index,
                    field: "student_id|faculty_number",
                    message: "student_id or faculty_number is required",
                });
                continue;
            }

            const resolvedById = await studentResolver.resolveById(rawStudentId);
            const resolvedByFaculty = await studentResolver.resolveByFacultyNumber(rawFacultyNumber);
            const resolvedStudent = resolvedById || resolvedByFaculty;

            if (resolvedById && resolvedByFaculty && Number(resolvedById.id) !== Number(resolvedByFaculty.id)) {
                conflictErrors.push({
                    index,
                    student_id: rawStudentId ?? null,
                    faculty_number: rawFacultyNumber ?? null,
                    message: "student_id and faculty_number resolve to different students",
                });
                continue;
            }

            if (!resolvedStudent) {
                validationErrors.push({
                    index,
                    field: "student_id|faculty_number",
                    message: "Unable to resolve student identity",
                });
                continue;
            }

            if (record.status !== undefined && record.status !== null && typeof record.status !== "string") {
                validationErrors.push({
                    index,
                    field: "status",
                    message: "status must be a string when provided",
                });
                continue;
            }

            const normalizedStatus = normalizeAttendanceStatus(record.status);

            const joinedAtParsed = parseOptionalIsoTimestamp(record.joined_at ?? record.joinedAt);
            if (!joinedAtParsed.ok) {
                validationErrors.push({
                    index,
                    field: "joined_at",
                    message: "joined_at must be a valid ISO timestamp or null",
                });
                continue;
            }

            const leftAtParsed = parseOptionalIsoTimestamp(record.left_at ?? record.leftAt);
            if (!leftAtParsed.ok) {
                validationErrors.push({
                    index,
                    field: "left_at",
                    message: "left_at must be a valid ISO timestamp or null",
                });
                continue;
            }

            if (joinedAtParsed.value && leftAtParsed.value) {
                const joinedAtMs = Date.parse(joinedAtParsed.value);
                const leftAtMs = Date.parse(leftAtParsed.value);
                if (Number.isFinite(joinedAtMs) && Number.isFinite(leftAtMs) && leftAtMs < joinedAtMs) {
                    validationErrors.push({
                        index,
                        field: "left_at",
                        message: "left_at must be after or equal to joined_at",
                    });
                    continue;
                }
            }

            const hasTimeWindow = Boolean(joinedAtParsed.value || leftAtParsed.value);
            if (!hasTimeWindow) {
                if (isPositiveAttendanceStatus(normalizedStatus)) {
                    validationErrors.push({
                        index,
                        field: "joined_at|left_at",
                        message: "Positive attendance statuses require joined_at or left_at",
                    });
                }
                continue;
            }

            const resolvedStudentId = Number(resolvedStudent.id);
            candidateRecords.push({
                studentId: resolvedStudentId,
                status: normalizedStatus,
                joinedAt: joinedAtParsed.value,
                leftAt: leftAtParsed.value,
                sessionKey: buildAttendanceSessionKey({
                    classId: classIdNum,
                    studentId: resolvedStudentId,
                    joinedAt: joinedAtParsed.value,
                    leftAt: leftAtParsed.value,
                }),
            });
        }

        if (conflictErrors.length > 0) {
            await client.query("ROLLBACK");
            transactionOpen = false;
            return res.status(409).send({
                error: "Conflicting student identifiers detected",
                conflicts: conflictErrors,
            });
        }

        if (validationErrors.length > 0) {
            await client.query("ROLLBACK");
            transactionOpen = false;
            return res.status(400).send({
                error: "Attendance finish payload validation failed",
                details: validationErrors,
            });
        }

        const uniqueRecordsBySessionKey = new Map();
        for (const row of candidateRecords) {
            uniqueRecordsBySessionKey.set(`${row.studentId}:${row.sessionKey}`, row);
        }
        const recordsToPersist = Array.from(uniqueRecordsBySessionKey.values());

        let insertedCount = 0;
        for (const row of recordsToPersist) {
            const existing = await client.query(
                `
                SELECT id
                FROM attendance_timestamps
                WHERE class_id = $1
                  AND student_id = $2
                  AND session_key = $3
                LIMIT 1
                FOR UPDATE
                `,
                [classIdNum, row.studentId, row.sessionKey]
            );

            if (existing.rows.length > 0) {
                await client.query(
                    `
                    UPDATE attendance_timestamps
                    SET
                        joined_at = COALESCE($1, joined_at),
                        left_at = COALESCE($2, left_at),
                        status = COALESCE($3, status),
                        class_name = COALESCE($4, class_name),
                        updated_at = NOW()
                    WHERE id = $5
                    `,
                    [row.joinedAt, row.leftAt, row.status, persistedClassName, existing.rows[0].id]
                );
            } else {
                insertedCount += 1;
                await client.query(
                    `
                    INSERT INTO attendance_timestamps (
                        class_id,
                        student_id,
                        session_key,
                        status,
                        class_name,
                        joined_at,
                        left_at,
                        created_at,
                        updated_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
                    `,
                    [classIdNum, row.studentId, row.sessionKey, row.status, persistedClassName, row.joinedAt, row.leftAt]
                );
            }
        }

        await recomputeAttendanceSummaryForClass(client, classIdNum);

        await client.query("COMMIT");
        transactionOpen = false;

        const statusCode = insertedCount > 0 ? 201 : 200;
        return res.status(statusCode).send({
            ok: true,
            saved: recordsToPersist.length,
        });
    } catch (error) {
        if (transactionOpen) {
            try {
                await client.query("ROLLBACK");
            } catch (rollbackError) {
                logRouteError(req, "ATTENDANCE_FINISH_ROLLBACK_ERROR", rollbackError);
            }
        }
        logRouteError(req, "ATTENDANCE_FINISH_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    } finally {
        client.release();
    }
});

// List attendance entries optionally filtered by classId: /attendance?classId=...
app.get("/attendance", async (req, res) => {
    logRequestStart(req);
    
    const classId = req.query.class_id;

    try {
        if (classId) {

            const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classId]);
            if (classCheck.rows.length === 0) {
                return res.status(404).send({ error: "Class not found" });
            }

            const rows = await pool.query(`
                SELECT a.id, a.class_id, a.student_id, a.count, s.full_name AS student_name
                FROM attendances a
                JOIN students s ON a.student_id = s.id
                WHERE a.class_id = $1
                ORDER BY a.updated_at DESC
            `, [classId]);
            return res.send({ message: "Attendance fetched", attendance: rows.rows });
        }


        const rows = await pool.query(`
            SELECT a.id, a.class_id, a.student_id, a.updated_at,
                         s.full_name AS student_name, c.name AS class_name
            FROM attendances a
            JOIN students s ON a.student_id = s.id
            JOIN classes c ON a.class_id = c.id
            ORDER BY a.updated_at DESC
        `);
        return res.send({ message: "All attendance fetched", attendance: rows.rows });
    } catch (error) {
        logRouteError(req, "ATTENDANCE_FETCH_ERROR", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Attendance Timestamps Endpoint -----------------
// Query: /attendance/timestamps?class_id=...
app.get("/attendance/timestamps", async (req, res) => {
    logRequestStart(req);

    const classId = req.query.class_id;

    if (!classId) {
        return res.status(400).send({ error: "class_id query parameter is required" });
    }

    const classIdNum = Number(classId);
    if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
        return res.status(400).send({ error: "class_id must be a valid number" });
    }

    try {
        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        if (classCheck.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        const rows = await pool.query(`
            SELECT 
                at.class_id,
                at.student_id,
                s.full_name,
                s.faculty_number,
                s.faculty_number_encrypted,
                at.joined_at,
                at.left_at
            FROM attendance_timestamps at
            JOIN students s ON at.student_id = s.id
            WHERE at.class_id = $1
            ORDER BY at.joined_at DESC
        `, [classIdNum]);

        const timestamps = rows.rows.map((row) => withAttendanceStudentIdentifiers(row));
        return res.send({ timestamps });
    } catch (error) {
        logRouteError(req, "ATTENDANCE_TIMESTAMPS_FETCH_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Attendance History Endpoint -----------------
// Query: /attendance/history?class_id=...&student_id=...&faculty_number=...
app.get("/attendance/history", async (req, res) => {
    logRequestStart(req);

    const { class_id, student_id, faculty_number } = req.query || {};

    if (!class_id) {
        return res.status(400).send({ error: "class_id is required" });
    }

    const classIdNum = Number(class_id);
    if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
        return res.status(400).send({ error: "class_id must be a valid number" });
    }

    try {
        let resolvedStudentId = null;

        if (student_id !== undefined && student_id !== null && String(student_id).length > 0) {
            const sid = Number(student_id);
            if (!Number.isFinite(sid) || sid <= 0) {
                return res.status(400).send({ error: "student_id must be a valid number" });
            }
            resolvedStudentId = sid;
        } else if (faculty_number) {
            const facNorm = normalize(faculty_number);
            const facHash = hashForLookup(facNorm);
            const studentCheck = await pool.query(
                "SELECT id FROM students WHERE faculty_number_hash = $1",
                [facHash]
            );
            if (studentCheck.rows.length === 0) {
                return res.status(404).send({ error: "Student not found" });
            }
            resolvedStudentId = studentCheck.rows[0].id;
        } else {
            return res.status(400).send({ error: "student_id or faculty_number is required" });
        }

        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        if (classCheck.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        const { rows } = await pool.query(
            `
            SELECT
                at.class_id,
                at.student_id,
                s.faculty_number,
                s.faculty_number_encrypted,
                at.joined_at,
                at.left_at
            FROM attendance_timestamps at
            JOIN students s ON s.id = at.student_id
            WHERE at.class_id = $1 AND at.student_id = $2
            ORDER BY at.joined_at DESC
            `,
            [classIdNum, resolvedStudentId]
        );

        const records = rows.map((row) => withAttendanceStudentIdentifiers(row));
        return res.status(200).send({ records });
    } catch (error) {
        logRouteError(req, "ATTENDANCE_HISTORY_FETCH_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Attendance Summary Endpoint -----------------
// Query: /attendance/summary?class_id=...
app.get("/attendance/summary", async (req, res) => {
    logRequestStart(req);

    const classId = req.query.class_id;

    if (!classId) {
        return res.status(400).send({ error: "class_id is required" });
    }

    const classIdNum = Number(classId);
    if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
        return res.status(400).send({ error: "class_id must be a valid number" });
    }

    try {
        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        if (classCheck.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        const { rows } = await pool.query(
            `
            SELECT 
                a.student_id,
                s.full_name,
                s.faculty_number,
                s.faculty_number_encrypted,
                COALESCE(a.count, 0) AS attendance_count
            FROM attendances a
            JOIN students s ON a.student_id = s.id
            WHERE a.class_id = $1
            ORDER BY s.full_name ASC
            `,
            [classIdNum]
        );

        const items = rows.map((row) => withAttendanceStudentIdentifiers(row));
        return res.status(200).send({ items });
    } catch (error) {
        logRouteError(req, "ATTENDANCE_SUMMARY_FETCH_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});



// ----------------- Remove Student from Class Endpoint -----------------
// Expects body: { class_id: number, faculty_number: string }
// Validates that teacher owns the class before deleting
app.post("/class_students/remove", requireTeacherAuth, async (req, res) => {
    logRequestStart(req);

    const classId = req.body.class_id;
    const facultyNumberRaw = req.body.faculty_number;
    const facultyNumber = facultyNumberRaw ? String(facultyNumberRaw).trim() : facultyNumberRaw;

    // Validate required fields
    if (!classId || !facultyNumber) {
        return res.status(400).send({ error: "class_id and faculty_number are required" });
    }
    try {
        // Step 0: Resolve student by faculty number.
        // Fast path uses hash, fallback handles legacy rows where hash/encrypted fields are missing.
        const facultyNorm = normalize(facultyNumber);
        const facultyHash = hashForLookup(facultyNorm);
        const fastStudentResult = await pool.query(
            `
            SELECT id, faculty_number, faculty_number_encrypted, faculty_number_hash
            FROM students
            WHERE faculty_number_hash = $1
            LIMIT 1
            `,
            [facultyHash]
        );

        let resolvedStudentRow = fastStudentResult.rows[0] || null;
        if (!resolvedStudentRow) {
            const fallbackCandidates = await pool.query(
                `
                SELECT id, faculty_number, faculty_number_encrypted, faculty_number_hash
                FROM students
                ORDER BY id ASC
                LIMIT 10000
                `
            );
            resolvedStudentRow = fallbackCandidates.rows.find((row) => {
                return identifierMatches({
                    inputNormalized: facultyNorm,
                    rowHash: row.faculty_number_hash,
                    rowPlain: row.faculty_number,
                    rowEncrypted: row.faculty_number_encrypted,
                });
            }) || null;
        }

        if (!resolvedStudentRow) {
            return res.status(404).send({ error: "Student not found with this faculty number" });
        }
        const student_id = resolvedStudentRow.id;

        const teacherId = req.authTeacherId;

        // Step 2: Verify teacher owns the class
        const classResult = await pool.query(
            "SELECT id, teacher_id FROM classes WHERE id = $1",
            [classId]
        );
        if (classResult.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }
        const classTeacherId = Number.parseInt(String(classResult.rows[0].teacher_id), 10);
        if (!Number.isInteger(classTeacherId) || classTeacherId !== teacherId) {
            return res.status(403).send({ error: "You do not have permission to modify this class" });
        }

        // Step 3: Verify student exists in class_students
        const studentInClassResult = await pool.query(
            "SELECT id FROM class_students WHERE class_id = $1 AND student_id = $2",
            [classId, student_id]
        );
        if (studentInClassResult.rows.length === 0) {
            return res.status(404).send({ error: "Student not found in this class" });
        }

        // Step 4: Delete the record from class_students
        const deleteResult = await pool.query(
            "DELETE FROM class_students WHERE class_id = $1 AND student_id = $2 RETURNING id",
            [classId, student_id]
        );

        res.status(200).send({ 
            message: "Student successfully removed from class",
            deletedRecord: deleteResult.rows[0]
        });

    } catch (error) {
        logRouteError(req, "CLASS_STUDENT_REMOVE_ERROR", error);
        res.status(500).send({ error: "Internal server error" });
    }
});




// Lightweight heartbeat endpoint: fast 204, no caching, accepts any method
app.all("/heartbeat", (req, res) => {
    logRequestStart(req, { includeBody: false });
    // Set no-cache headers
    res.set({
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "Surrogate-Control": "no-store"
    });
    // No body needed; 204 keeps it minimal and fast
    res.status(204).end();
});





app.post("/save_student_timestamps", async (req, res) => {
    logRequestStart(req);

    const classIdNum = parsePositiveInteger(req.body.class_id);
    const studentFacultyNumber = req.body.faculty_number;
    const joinedAtParsed = parseOptionalIsoTimestamp(req.body.joined_at);
    const leftAtParsed = parseOptionalIsoTimestamp(req.body.left_at);

    if (!classIdNum) {
        return res.status(400).send({ error: "class_id must be a valid positive integer" });
    }
    if (!studentFacultyNumber || !String(studentFacultyNumber).trim()) {
        return res.status(400).send({ error: "faculty_number is required" });
    }
    if (!joinedAtParsed.ok || !leftAtParsed.ok) {
        return res.status(400).send({ error: "joined_at and left_at must be valid ISO timestamps" });
    }
    if (!joinedAtParsed.value && !leftAtParsed.value) {
        return res.status(400).send({ error: `${studentFacultyNumber} has not been marked as attended.` });
    }

    if (joinedAtParsed.value && leftAtParsed.value) {
        const joinedAtMs = Date.parse(joinedAtParsed.value);
        const leftAtMs = Date.parse(leftAtParsed.value);
        if (Number.isFinite(joinedAtMs) && Number.isFinite(leftAtMs) && leftAtMs < joinedAtMs) {
            return res.status(400).send({ error: "left_at must be after or equal to joined_at" });
        }
    }

    const client = await pool.connect();
    let transactionOpen = false;

    try {
        await client.query("BEGIN");
        transactionOpen = true;
        await client.query("SELECT pg_advisory_xact_lock($1::bigint)", [classIdNum]);

        const classCheck = await client.query(
            `
            SELECT id, name
            FROM classes
            WHERE id = $1
            LIMIT 1
            `,
            [classIdNum]
        );
        if (!classCheck.rows.length) {
            await client.query("ROLLBACK");
            transactionOpen = false;
            return res.status(404).send({ error: "Class not found" });
        }

        const studentResolver = buildAttendanceStudentResolver(client);
        const studentRow = await studentResolver.resolveByFacultyNumber(studentFacultyNumber);
        if (!studentRow?.id) {
            await client.query("ROLLBACK");
            transactionOpen = false;
            return res.status(404).send({ error: "Student not found in database." });
        }
        const studentId = Number(studentRow.id);

        const sessionKey = buildAttendanceSessionKey({
            classId: classIdNum,
            studentId,
            joinedAt: joinedAtParsed.value,
            leftAt: leftAtParsed.value,
        });

        const existing = await client.query(
            `
            SELECT id
            FROM attendance_timestamps
            WHERE class_id = $1
              AND student_id = $2
              AND session_key = $3
            LIMIT 1
            FOR UPDATE
            `,
            [classIdNum, studentId, sessionKey]
        );

        if (existing.rows.length > 0) {
            await client.query(
                `
                UPDATE attendance_timestamps
                SET
                    joined_at = COALESCE($1, joined_at),
                    left_at = COALESCE($2, left_at),
                    status = COALESCE(status, 'completed'),
                    class_name = COALESCE(class_name, $3),
                    updated_at = NOW()
                WHERE id = $4
                `,
                [joinedAtParsed.value, leftAtParsed.value, classCheck.rows[0].name || null, existing.rows[0].id]
            );
        } else {
            await client.query(
                `
                INSERT INTO attendance_timestamps (
                    class_id,
                    student_id,
                    session_key,
                    status,
                    class_name,
                    joined_at,
                    left_at,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, $3, 'completed', $4, $5, $6, NOW(), NOW())
                `,
                [classIdNum, studentId, sessionKey, classCheck.rows[0].name || null, joinedAtParsed.value, leftAtParsed.value]
            );
        }

        await recomputeAttendanceSummaryForClass(client, classIdNum);
        await client.query("COMMIT");
        transactionOpen = false;

        return res.send({
            message: "Student timestamps saved"
        });
    } catch (error) {
        if (transactionOpen) {
            try {
                await client.query("ROLLBACK");
            } catch (rollbackError) {
                logRouteError(req, "SAVE_TIMESTAMPS_ROLLBACK_ERROR", rollbackError);
            }
        }
        logRouteError(req, "SAVE_TIMESTAMPS_ERROR", error);
        return res.status(500).send({ error: "Internal server error" });
    } finally {
        client.release();
    }

});



app.get("/get_student_attendance_count", async (req, res) => {
    logRequestStart(req);

    var classId = req.query.class_id;
    var studentId = req.query.student_id;
    var facultyNumber = req.query.faculty_number;


    if (!classId || (!studentId && !facultyNumber)) {
        return res.status(400).send({ error: "class_id and student_id or faculty_number are required" });
    }

    const classIdNum = Number(classId);
    if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
        return res.status(400).send({ error: "class_id must be a valid number" });
    }

    let studentIdNum = null;
    const resolveFacultyNumber = facultyNumber || studentId;

    if (resolveFacultyNumber) {
        const facNorm = normalize(resolveFacultyNumber);
        const facHash = hashForLookup(facNorm);
        const studentLookup = await pool.query(
            "SELECT id FROM students WHERE faculty_number_hash = $1",
            [facHash]
        );
        if (studentLookup.rows.length === 0) {
            return res.status(404).send({ error: "Student not found" });
        }
        studentIdNum = studentLookup.rows[0].id;
    } else {
        return res.status(400).send({ error: "student_id or faculty_number is required" });
    }

    const sqlForStudentAttendance = `
        SELECT COALESCE((SELECT count FROM attendances WHERE class_id = $1 AND student_id = $2), 0) AS count
    `;

    const sqlForTotalCompletedClasses = `
        SELECT COALESCE(completed_classes_count, 0) AS completed_classes_count FROM classes WHERE id = $1
    `;

    const result  = await pool.query(sqlForStudentAttendance, [classIdNum, studentIdNum]);
    const result2 = await pool.query(sqlForTotalCompletedClasses, [classIdNum]);


    const attendanceCount = Number(result.rows[0]?.count ?? 0);
    const totalCompletedClassesCount = Number(result2.rows[0]?.completed_classes_count ?? 0);
    

    
    return res.send({
        message: "Student attendance count fetched",
        attendance_count: attendanceCount,
        total_completed_classes_count: totalCompletedClassesCount
    });

});



app.post("/update_completed_classes_count", requireTeacherAuth, async (req, res) => {
    logRequestStart(req);
    
    var classId = req.body.class_id;


    const sql = `UPDATE classes SET completed_classes_count = completed_classes_count + 1 WHERE id = $1 AND teacher_id = $2`;
    const result  = await pool.query(sql, [classId, req.authTeacherId]);
    if (result.rowCount === 0) {
        return res.status(404).send({ error: "Class not found for this teacher" });
    }

    
    return res.send({
        message: "Completed classes count updated"
    });

});



const { GoogleGenerativeAI } = require("@google/generative-ai");
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const SUPPORT_SYSTEM_PROMPT = `You are 'CheckMate', the friendly and knowledgeable support assistant for StudentCheck, a student attendance tracking platform.

Your primary goal is to help users solve their problems with the StudentCheck platform quickly and effectively.

Core Instructions:
- **Persona & Tone**: Be patient, empathetic, and clear. Maintain a friendly, professional, and encouraging tone. It's okay to use emojis sparingly to convey friendliness (like 👍 or 😊).
- **Capabilities**: You are an expert on the StudentCheck platform. You can answer questions about features, troubleshoot common issues (like login problems or data not appearing), and guide users through processes like creating classes, managing students, and tracking attendance.
- **Formatting**: Use markdown (like bullet points or bold text) to make complex information easy to understand. For step-by-step instructions, always use numbered lists.
- **Boundaries**: If a user asks a question unrelated to the StudentCheck platform (e.g., general knowledge, math problems, personal advice), you must politely decline. State that you can only help with StudentCheck-related inquiries. Do not attempt to answer off-topic questions.
- **Conciseness**: While being friendly, keep your answers as concise as possible. Get straight to the solution.

Example Interaction:

User: "my students aren't showing up in the attendance summary"

Good Response:
"I'm sorry to hear you're having trouble with the attendance summary! That can be frustrating.

A common reason for this is that the attendance session hasn't been 'finished' yet. Here’s how to do that:
1. Go to the attendance page for your class.
2. Click the **'Finish Session'** button.

This processes all the timestamps and updates the summary. Let me know if that solves it for you! 👍"
`;

app.post("/support/chat", async (req, res) => {
    logRequestStart(req, {includeBody: false});

    const { message, history } = req.body || {};

    if(!message || typeof message !== "string" || !message.trim()){
        return res.status(400).send({ error: "message is required"})
    }

    const chatHistory = [
        { role: "user", parts: [{ text: `System Instruction: ${SUPPORT_SYSTEM_PROMPT}` }] },
        { role: "model", parts: [{ text: "Understood. I am ready to help." }] }
    ];

    if(Array.isArray(history)){
        for(const entry of history){
            if(entry && typeof entry.role === "string" && typeof entry.content === "string" && entry.content.trim() !== "" && ["user", "model"].includes(entry.role)){
                const text = entry.content.slice(0, 1000); // Limit content length for safety
                if (chatHistory.length === 0) {
                    // Gemini requires the chat history to always start with a 'user' message.
                    if (entry.role === "user") {
                        chatHistory.push({ role: "user", parts: [{ text }] });
                    }
                } else {
                    const lastMessage = chatHistory[chatHistory.length - 1];
                    // Combine consecutive messages of the same role to maintain strict alternation
                    if (lastMessage.role === entry.role) {
                        lastMessage.parts[0].text += "\n" + text;
                    } else {
                        chatHistory.push({ role: entry.role, parts: [{ text }] });
                    }
                }
            }
        }

        // The history passed to startChat must end with a 'model' message so the new sendMessage('user') maintains alternation.
        if (chatHistory.length > 0 && chatHistory[chatHistory.length - 1].role === "user") {
            chatHistory.pop();
        }
    }

    try {
        const model = genAI.getGenerativeModel({
            model: "gemini-1.5-flash-latest",
            generationConfig: {
                maxOutputTokens: 120,  //  // Limit length   
                temperature: 0.2,       // lower = more controlled
                topP: 0.8,              
            },
        }, { apiVersion: "v1" });

        const chat = model.startChat({history: chatHistory});
        const result = await chat.sendMessage(message.slice(0, 1000));
        
        let reply;
        try {
            reply = result.response.text();
        } catch (textError) {
            // Handle cases where the response is blocked by safety settings
            reply = "I'm sorry, but I cannot fulfill that request due to safety restrictions.";
        }
        reply = reply || "Sorry, I couldn't generate a response.";
        
        return res.send({ reply });
    } catch (error) {
        logRouteError(req, "SUPPORT_CHAT_ERROR", error);
        const errorMessage = error?.message || "Support service unavailable";
        return res.status(500).send({ error: `Gemini API Error: ${errorMessage}` });
    }
});






const { exportBackup, downloadBackup, encryptBackup, decryptBackup, encryptUserFields, dropEncryptionColumns, importBackup } = createBackupHandlers({ pool, logRequestStart });

// ----------------- Database Backup Export Endpoint -----------------
app.get("/backup/export", exportBackup);

// ----------------- Database Backup Download Endpoint -----------------
app.get("/backup/download", downloadBackup);

// ----------------- Database Backup Encrypt Endpoint -----------------
app.post("/backup/encrypt", encryptBackup);

// ----------------- Database Backup Decrypt Endpoint -----------------
app.post("/backup/decrypt", decryptBackup);

// ----------------- Database Backup Encrypt User Fields Endpoint -----------------
app.post("/backup/encrypt-user-fields", encryptUserFields);

// ----------------- Drop Encryption/Hash Columns Endpoint -----------------
app.post("/backup/drop-encryption-columns", dropEncryptionColumns);

// ----------------- Database Backup Import Endpoint -----------------
app.post("/backup/import", importBackup);

app.listen(PORT, () => {
    emitLog("info", "SERVER_LISTENING", {
        port: Number(PORT),
        nodeEnv: process.env.NODE_ENV || "development",
    });
});
