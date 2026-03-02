const PORT = process.env.PORT || 3000;
const DATABASE_URL = "postgresql://postgres:Flame-Supabase01!@db.imnqwnpsuapkbbnuufqn.supabase.co:5432/postgres";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg"); // PostgreSQL client
const Stripe = require("stripe");
const { createDbAdapter } = require("./dbAdapter");
const { createStripeService } = require("./stripeService");
const { createBackupHandlers } = require("./backupService");
const { createBillingRouter, createBillingWebhookHandler } = require("./billingRoutes");
const { encryptRaw, decrypt, hashForLookup, hashExactForLookup, normalize } = require("./security/cryptoService");
const { inflateStudent } = require("./security/decryptors");
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

if (!String(process.env.AUTH_PEPPER || "").trim()) {
    throw new Error("AUTH_PEPPER is required");
}
if (!JWT_SECRET) {
    throw new Error("JWT_SECRET (or AUTH_TOKEN_SECRET) is required");
}

const app = express();

// ----------------- Structured Logging Helpers -----------------
const rawLog = console.log.bind(console);
const rawError = console.error.bind(console);

const logDivider = () => rawLog("============================================================");

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

const scrubRequestBody = (body) => {
    if (!body || typeof body !== "object") return body;
    const cleaned = { ...body };
    const sensitiveKeys = [
        "password",
        "password_hash",
        "passwordHash",
        "token",
        "accessToken",
        "refreshToken",
        "email",
        "facultyNumber",
        "faculty_number",
    ];
    for (const key of sensitiveKeys) {
        if (Object.prototype.hasOwnProperty.call(cleaned, key)) {
            cleaned[key] = "[REDACTED]";
        }
    }
    return cleaned;
};

const logRequestStart = (req, options = {}) => {
    const { note, includeBody = true } = options;
    logDivider();
    rawLog(`[REQUEST] ${formatBgTime()} ${req.method} ${req.originalUrl}`);
    if (note) {
        rawLog(`[REQUEST] Note: ${note}`);
    }
    const query = req.query || {};
    if (Object.keys(query).length) {
        rawLog("[REQUEST] Query:", query);
    }
    if (includeBody && req.body && Object.keys(req.body).length) {
        rawLog("[REQUEST] Body:", scrubRequestBody(req.body));
    }
    logDivider();
};

console.log = (...args) => rawLog(`[INFO ${formatBgTime()}]`, ...args);
console.error = (...args) => rawError(`[ERROR ${formatBgTime()}]`, ...args);

const addStudentsToClass = async (classId, students) => {
    console.log("[CLASS STUDENTS] Begin assignment");
    console.log("[CLASS STUDENTS] classId:", classId);
    console.log("[CLASS STUDENTS] students payload:", students);

    const facultyNumbers = students
        .map(s => {
            if (typeof s === "string" || typeof s === "number") {
                return String(s);
            }
            return s?.facultyNumber || s?.faculty_number;
        })
        .filter(Boolean)
        .map((value) => normalize(String(value)));

    console.log("[CLASS STUDENTS] facultyNumbers:", facultyNumbers);

    if (facultyNumbers.length === 0) {
        console.log("[CLASS STUDENTS] No valid faculty numbers provided");
        return { assignedCount: 0, facultyNumbers: [] };
    }

    const normalizedToHash = new Map();
    for (const fac of facultyNumbers) {
        normalizedToHash.set(fac, hashForLookup(fac));
    }

    const hashes = Array.from(new Set(Array.from(normalizedToHash.values())));
    const placeholders = hashes.map((_, i) => `$${i + 1}`).join(",");
    console.log("[CLASS STUDENTS] placeholders:", placeholders);

    const selectSql = `SELECT id, faculty_number_hash FROM students WHERE faculty_number_hash IN (${placeholders})`;
    console.log("[CLASS STUDENTS] selectSql:", selectSql);

    const result = await pool.query(selectSql, hashes);
    console.log("[CLASS STUDENTS] students matched:", result.rows);

    const idMap = {};
    result.rows.forEach(row => {
        idMap[row.id] = row.faculty_number_hash;
    });

    const insertSql = "INSERT INTO class_students (class_id, student_id) VALUES ($1, $2) ON CONFLICT DO NOTHING";
    const studentIds = Object.keys(idMap);
    console.log("[CLASS STUDENTS] studentIds:", studentIds);

    let addedCount = 0;
    for (const id of studentIds) {
        console.log("[CLASS STUDENTS] Assigning student_id:", id, "faculty_number:", idMap[id]);
        const insertRes = await pool.query(insertSql, [classId, id]);
        addedCount += insertRes.rowCount || 0;
    }

    console.log("[CLASS STUDENTS] Assignment complete");
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
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // we'll use this later
  host: "db.imnqwnpsuapkbbnuufqn.supabase.co",
  ssl: {
    rejectUnauthorized: false, // 🔒 required for Render
  },
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
    console.log(`[HEALTHZ] ping from ${req.ip} at ${new Date().toISOString()}`);
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
    console.log("[AUTH_EVENT]", details);
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
console.log("[MIGRATION] APPLY_ENCRYPTION_MIGRATION =", APPLY_ENCRYPTION_MIGRATION);
console.log("[MIGRATION] APPLY_ENCRYPTION_BACKFILL =", APPLY_ENCRYPTION_BACKFILL);

const applyEncryptionMigration = async (client) => {
    console.log("[MIGRATION] Applying encryption/hash columns migration (if needed)...");
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
    console.log("[MIGRATION] Encryption/hash columns migration completed (or already in place).");
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
    console.log("[BACKFILL] Starting backfill for students/teachers encrypted + hash fields (email + faculty)...");

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
    console.log(`[BACKFILL] Students checked: ${studentRows.length}, updated: ${studentsUpdated}`);

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
    console.log(`[BACKFILL] Teachers checked: ${teacherRows.length}, updated: ${teachersUpdated}`);

    console.log("[BACKFILL] Backfill completed.");
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
    console.log(`[DB] Tables discovered in public schema: ${rows.length}`);

    for (const row of rows) {
        console.log(`[DB] Table ${row.tablename}: OK`);
    }

    const missingTables = requiredTables.filter((tableName) => !existingTables.has(tableName));
    for (const tableName of missingTables) {
        console.log(`[DB] Table ${tableName}: MISSING`);
    }
};





(async () => {
  let client;
  try {
    client = await pool.connect();
    console.log("[DB] Connected to PostgreSQL.");

    const result = await client.query("SELECT NOW() AS server_time");
    console.log("[DB] Server time:", formatServerTime(result.rows[0]?.server_time));
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
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(class_id, student_id)
            );
        `);
        await db.ensureBillingTables();
        await verifyAndPrintTables(client);
        if (APPLY_ENCRYPTION_MIGRATION) {
            await applyEncryptionMigration(client);
        } else {
            console.log("[MIGRATION] APPLY_ENCRYPTION_MIGRATION=false, skipping encryption/hash migration.");
        }
        if (APPLY_ENCRYPTION_BACKFILL) {
            await backfillEncryptionForExistingData(client);
        } else {
            console.log("[BACKFILL] APPLY_ENCRYPTION_BACKFILL=false, skipping encryption/hash backfill.");
        }
  } catch (err) {
    console.error("[DB] Startup initialization error:", err);
  } finally {
    if (client) {
        client.release();
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
    const fromEncryptedColumn = tryDecryptValue(row.email_encrypted);
    if (fromEncryptedColumn) return fromEncryptedColumn;

    const fromEmailColumn = tryDecryptValue(row.email);
    if (fromEmailColumn) return fromEmailColumn;

    return row.email;
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

        console.log("[AUTH] Checking teacher credentials");

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
        console.error("[AUTH] Database error during teacher login:", error);
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

        console.log("[AUTH] Checking student credentials");

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

        const student = inflateStudent({
            ...studentRow,
            ...updates,
        });

        return res.send({
            message: "Student login successful",
            student,
            loginSuccess: true
        });
    } catch (error) {
        console.error("[AUTH] Database error during student login:", error);
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
            RETURNING full_name, email, faculty_number, "group", course, faculty, level, specialization
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

        const student = {
            ...result.rows[0],
            email: normalizedEmail,
            faculty_number: normalizedFacultyNumber,
        };
        return res.send({ message: "User registration successful", student, registrationSuccess: true });
    } catch (error) {
        const mapped = mapRegistrationUniqueViolation(error);
        if (mapped && mapped.type === "duplicate_email") {
            console.warn("[REGISTRATION][DUPLICATE_EMAIL]", { requestId, constraint: mapped.constraint });
            return res.status(409).send({
                error: "Registration failed. Please use a different email or faculty number.",
                conflicts: { email: true, facultyNumber: false },
                registrationSuccess: false
            });
        }
        if (mapped && mapped.type === "duplicate_faculty_number") {
            console.warn("[REGISTRATION][DUPLICATE_FACULTY]", { requestId, constraint: mapped.constraint });
            return res.status(409).send({
                error: "Registration failed. Please use a different email or faculty number.",
                conflicts: { email: false, facultyNumber: true },
                registrationSuccess: false
            });
        }
        if (mapped && mapped.type === "id_collision") {
            console.error("[REGISTRATION][ID_COLLISION_UNRECOVERED]", {
                requestId,
                constraint: mapped.constraint,
                retryFailed: Boolean(error.registrationRetryFailed),
            });
            return res.status(500).send({ error: "Internal server error", registrationSuccess: false });
        }
        // Unique violation (email or other unique columns)
        if (error && error.code === '23505') {
            console.warn('⚠️ Duplicate registration attempt:', error.detail || error.constraint);
            return res.status(409).send({ 
                error: "Registration failed. Please use a different email or faculty number.",
                registrationSuccess: false
            });
        }
        console.error("❌ Database error during registration:", error);
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
        const students = result.rows.map(inflateStudent);
        return res.send({ students });
    } catch (error) {
        console.error("❌ Database error fetching students:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});


// ----------------- Class Creation Endpoint -----------------
// Expects body: { name: string, students?: Array }
app.post("/classes", requireTeacherAuth, async (req, res) => {
    logRequestStart(req);

    const { name, students } = req.body || {};

    if (!name) {
        console.log("[CLASS CREATE] Validation failed: name is missing");
        return res.status(400).send({ error: "Class name is required" });
    }
    try {
        console.log("[CLASS CREATE] Step 1: Resolve teacher from auth token");
        const teacherId = req.authTeacherId;
        console.log("[CLASS CREATE] Teacher resolved -> id:", teacherId);

        console.log("[CLASS CREATE] Step 2: Insert class");
        console.log("[CLASS CREATE] Insert payload:", { teacher_id: teacherId, name });

        const insertResult = await pool.query(
            "INSERT INTO classes (teacher_id, name) VALUES ($1, $2) RETURNING id, teacher_id, name",
            [teacherId, name]
        );

        const created = insertResult.rows[0];

        console.log("[CLASS CREATE] Insert result rows:", insertResult.rows);
        console.log("[CLASS CREATE] Created class:", created);
        if (Array.isArray(students) && students.length > 0) {
            console.log("[CLASS CREATE] Step 3: Assigning students to class");
            const assignmentResult = await addStudentsToClass(created.id, students);
            console.log("[CLASS CREATE] Assignment result:", assignmentResult);
        } else {
            console.log("[CLASS CREATE] Step 3: No students provided, skipping assignment");
        }

        console.log("[CLASS CREATE] Step 4: Responding with created class");
        res.status(201).send({ message: "Class created", class: created });

    } catch (error) {
        console.error("❌ Database error creating class:", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// (Optional helper) List classes for a teacher by email query param: /classes?teacherEmail=...
app.get("/classes", async (req, res) => {
    logRequestStart(req);
    const { teacherEmail } = req.query;
    try {
        if (teacherEmail) {
            const teacherEmailNorm = normalize(teacherEmail);
            const teacherEmailHash = hashForLookup(teacherEmailNorm);
            const t = await pool.query("SELECT id FROM teachers WHERE email_hash = $1", [teacherEmailHash]);
            if (t.rows.length === 0) {
                return res.status(404).send({ error: "Teacher not found" });
            }
            const teacherId = t.rows[0].id;
            console.log("Fetching classes for teacher ID:", teacherId);

            const classes = await pool.query("SELECT id, teacher_id, name FROM classes WHERE teacher_id = $1 ORDER BY id DESC", [teacherId]);
            console.log("Classes fetched:", classes.rows);
            
            return res.send({ message: "Classes fetched", classes: classes.rows });
        } else {
            const classes = await pool.query("SELECT id, teacher_id, name FROM classes ORDER BY id DESC");
            return res.send({ message: "All classes fetched", classes: classes.rows });
        }
    } catch (error) {
        console.error("❌ Database error fetching classes:", error);
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
        console.error("❌ Database error renaming class:", error);
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
        console.error("❌ Database error deleting class:", error);
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
    var classId = req.query.class_id;
    console.log("classId:", classId);
    if (!classId) {
        return res.status(400).send({ error: "class_id query parameter is required" });
    }
    var result  = await pool.query("SELECT * FROM class_students WHERE class_id = $1", [classId]);
    console.log('Query result:', result.rows);

    // get student details for each student_id
    var studentIds = [];
    result.rows.forEach(row => {
        var studentId = row.student_id;
        console.log("Student ID in class:", studentId);
        studentIds.push(studentId);
    });

    console.log("Student IDs in class:", studentIds);

    // Fetch details for these students
    let studentsDetails = [];
    if (studentIds.length > 0) {
        const placeholders = studentIds.map((_, i) => `$${i + 1}`).join(',');
        const sql = `SELECT id, full_name, faculty_number FROM students WHERE id IN (${placeholders})`;
        const detailsRes = await pool.query(sql, studentIds);
        studentsDetails = detailsRes.rows;
    }

    console.log("Students details fetched:", studentsDetails);

    return res.send({
        message: "Class students fetched",
        students: studentsDetails // add names and faculty numbers by id
    });
});





app.get("/get_student_classes", async (req, res) => {
    logRequestStart(req);

    const rawStudentId = req.query.student_id;
    console.log("studentId (raw):", rawStudentId);

    if (!rawStudentId || rawStudentId === "undefined" || rawStudentId === "null") {
        return res.status(400).send({ error: "student_id query parameter is required" });
    }

    const studentId = Number(rawStudentId);
    if (!Number.isFinite(studentId) || studentId <= 0) {
        return res.status(400).send({ error: "student_id must be a valid number" });
    }

    const sql = `SELECT * FROM class_students WHERE student_id = $1`;
    const result  = await pool.query(sql, [studentId]);

    console.log('Query result:', result.rows);




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





    console.log("Class names:", classNames);

    return res.send({
        message: "Student classes fetched",
        class_names: classNames
    });

});





app.get("/get_class_id_by_name", async (req, res) => {
    logRequestStart(req);

    var className = req.query.class_name;
    console.log("className:", className);

    const sql = `SELECT id FROM classes WHERE name = $1`;
    const result  = await pool.query(sql, [className]);

    console.log('Query result:', result.rows);

    if (result.rows.length === 0) {
        return res.status(404).send({ error: "Class not found" });
    }

    const class_id = result.rows[0].id;

    console.log("Class ID:", class_id);

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

    console.log("[ATTENDANCE] Body:", req.body);
    console.log("[ATTENDANCE] class_id:", class_id);
    console.log("[ATTENDANCE] student_ids:", student_ids);
    console.log("[ATTENDANCE] student_id:", student_id);
    console.log("[ATTENDANCE] faculty_number:", faculty_number);

    if (!class_id || (!student_ids && !student_id && !faculty_number)) {
        console.log("[ATTENDANCE] Validation failed: missing required fields");
        return res.status(400).send({ error: "class_id and student_id or faculty_number are required" });
    }

    try {
        const classIdNum = Number(class_id);
        if (!Number.isFinite(classIdNum) || classIdNum <= 0) {
            return res.status(400).send({ error: "class_id must be a valid number" });
        }

        // Verify class exists
        console.log("[ATTENDANCE] Checking class existence");
        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        console.log("[ATTENDANCE] classCheck.rows:", classCheck.rows);
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
            console.log("[ATTENDANCE] Branch: student_ids array");
            const studentIdsInt = student_ids
                .map(value => Number(value))
                .filter(Number.isFinite);

            const uniqueIds = Array.from(new Set(studentIdsInt));

            if (uniqueIds.length === 0) {
                return res.status(400).send({ error: "No valid student_ids provided" });
            }

            const results = [];
            console.log("[ATTENDANCE] Processing attendance for IDs:", uniqueIds);
            for (const sid of uniqueIds) {
                console.log(`[ATTENDANCE] Recording attendance class_id=${classIdNum}, student_id=${sid}`);
                const { rows } = await pool.query(upsertSql, [classIdNum, sid]);
                results.push(rows[0]);
            }

            console.log("[ATTENDANCE] Results:", results);
            return res.status(200).send({ success: true, attendance: results });
        }

        // Branch 2: single student_id or faculty_number
        console.log("[ATTENDANCE] Branch: single student");
        let resolvedStudentId = null;

        if (student_id !== undefined && student_id !== null) {
            const sid = Number(student_id);
            if (!Number.isFinite(sid) || sid <= 0) {
                return res.status(400).send({ error: "student_id must be a valid number" });
            }
            console.log("[ATTENDANCE] Looking up student by id:", sid);
            const studentCheck = await pool.query("SELECT id FROM students WHERE id = $1", [sid]);
            console.log("[ATTENDANCE] studentCheck.rows:", studentCheck.rows);
            if (studentCheck.rows.length === 0) {
                return res.status(404).send({ error: "Student not found" });
            }
            resolvedStudentId = sid;
            console.log("[ATTENDANCE] Resolved student_id:", resolvedStudentId);
        } else if (faculty_number) {
            console.log("[ATTENDANCE] Looking up student by faculty_number:", faculty_number);
            const facNorm = normalize(faculty_number);
            const facHash = hashForLookup(facNorm);
            const studentCheck = await pool.query(
                "SELECT id FROM students WHERE faculty_number_hash = $1",
                [facHash]
            );
            console.log("[ATTENDANCE] studentCheck.rows:", studentCheck.rows);
            if (studentCheck.rows.length === 0) {
                return res.status(404).send({ error: "Student not found" });
            }
            resolvedStudentId = studentCheck.rows[0].id;
            console.log("[ATTENDANCE] Resolved student_id from faculty_number:", resolvedStudentId);
        }

        if (!resolvedStudentId) {
            return res.status(400).send({ error: "student_id or faculty_number is required" });
        }

        console.log("[ATTENDANCE] Upserting attendance with:", { classIdNum, resolvedStudentId });
        const { rows } = await pool.query(upsertSql, [classIdNum, resolvedStudentId]);
        console.log("[ATTENDANCE] Result:", rows[0]);
        return res.status(200).send({ success: true, attendance: rows[0] });
    } catch (error) {
        console.error("❌ Database error recording attendance:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// List attendance entries optionally filtered by classId: /attendance?classId=...
app.get("/attendance", async (req, res) => {
    logRequestStart(req);
    
    const classId = req.query.class_id;
    const studentId = req.query.student_id;

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
                ORDER BY a.timestamp DESC
            `, [classId]);
            return res.send({ message: "Attendance fetched", attendance: rows.rows });
        }


        const rows = await pool.query(`
            SELECT a.id, a.class_id, a.student_id, a.timestamp,
                         s.full_name AS student_name, c.name AS class_name
            FROM attendances a
            JOIN students s ON a.student_id = s.id
            JOIN classes c ON a.class_id = c.id
            ORDER BY a.timestamp DESC
        `);
        return res.send({ message: "All attendance fetched", attendance: rows.rows });
    } catch (error) {
        console.error("❌ Database error fetching attendance:", error);
        res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Attendance Timestamps Endpoint -----------------
// Query: /attendance/timestamps?class_id=...
app.get("/attendance/timestamps", async (req, res) => {
    logRequestStart(req);

    const classId = req.query.class_id;
    console.log("[ATTENDANCE TIMESTAMPS] class_id:", classId);

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
                at.joined_at,
                at.left_at
            FROM attendance_timestamps at
            JOIN students s ON at.student_id = s.id
            WHERE at.class_id = $1
            ORDER BY at.joined_at DESC
        `, [classIdNum]);

        return res.send({ timestamps: rows.rows });
    } catch (error) {
        console.error("❌ Database error fetching attendance timestamps:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Attendance History Endpoint -----------------
// Query: /attendance/history?class_id=...&student_id=...&faculty_number=...
app.get("/attendance/history", async (req, res) => {
    logRequestStart(req);

    const { class_id, student_id, faculty_number } = req.query || {};
    console.log("[ATTENDANCE HISTORY] class_id:", class_id);
    console.log("[ATTENDANCE HISTORY] student_id:", student_id);
    console.log("[ATTENDANCE HISTORY] faculty_number:", faculty_number);

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
            console.log("[ATTENDANCE HISTORY] Using student_id:", resolvedStudentId);
        } else if (faculty_number) {
            console.log("[ATTENDANCE HISTORY] Resolving student by faculty_number:", faculty_number);
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
            console.log("[ATTENDANCE HISTORY] Resolved student_id:", resolvedStudentId);
        } else {
            return res.status(400).send({ error: "student_id or faculty_number is required" });
        }

        const classCheck = await pool.query("SELECT id FROM classes WHERE id = $1", [classIdNum]);
        if (classCheck.rows.length === 0) {
            return res.status(404).send({ error: "Class not found" });
        }

        const { rows } = await pool.query(
            `
            SELECT joined_at, left_at
            FROM attendance_timestamps
            WHERE class_id = $1 AND student_id = $2
            ORDER BY joined_at DESC
            `,
            [classIdNum, resolvedStudentId]
        );

        return res.status(200).send({ records: rows });
    } catch (error) {
        console.error("❌ Database error fetching attendance history:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});

// ----------------- Attendance Summary Endpoint -----------------
// Query: /attendance/summary?class_id=...
app.get("/attendance/summary", async (req, res) => {
    logRequestStart(req);

    const classId = req.query.class_id;
    console.log("[ATTENDANCE SUMMARY] class_id:", classId);

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
                COALESCE(a.count, 0) AS attendance_count
            FROM attendances a
            JOIN students s ON a.student_id = s.id
            WHERE a.class_id = $1
            ORDER BY s.full_name ASC
            `,
            [classIdNum]
        );

        return res.status(200).send({ items: rows });
    } catch (error) {
        console.error("❌ Database error fetching attendance summary:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
});



// ----------------- Remove Student from Class Endpoint -----------------
// Expects body: { class_id: number, faculty_number: string }
// Validates that teacher owns the class before deleting
app.post("/class_students/remove", requireTeacherAuth, async (req, res) => {
    logRequestStart(req);

    const classId = req.body.class_id ?? req.body.classId;
    const facultyNumberRaw = req.body.faculty_number ?? req.body.facultyNumber;
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
        console.log("Student ID found:", student_id);

        const teacherId = req.authTeacherId;
        console.log("Teacher ID found:", teacherId);

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
        console.log("Teacher ownership verified for class:", classId);

        // Step 3: Verify student exists in class_students
        const studentInClassResult = await pool.query(
            "SELECT id FROM class_students WHERE class_id = $1 AND student_id = $2",
            [classId, student_id]
        );
        if (studentInClassResult.rows.length === 0) {
            return res.status(404).send({ error: "Student not found in this class" });
        }
        console.log("Student found in class");

        // Step 4: Delete the record from class_students
        const deleteResult = await pool.query(
            "DELETE FROM class_students WHERE class_id = $1 AND student_id = $2 RETURNING id",
            [classId, student_id]
        );
        console.log("Student removed from class:", deleteResult.rows[0]);

        res.status(200).send({ 
            message: "Student successfully removed from class",
            deletedRecord: deleteResult.rows[0]
        });

    } catch (error) {
        console.error("❌ Database error removing student from class:", error);
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
    
    var classId = req.body.class_id;
    var studentFacultyNumber = req.body.faculty_number;

    const facNorm = normalize(studentFacultyNumber);
    const facHash = hashForLookup(facNorm);

    const studentIdQueryResult = await pool.query(
        "SELECT id FROM students WHERE faculty_number_hash = $1",
        [facHash]
    );

    const studentId = Number(studentIdQueryResult.rows[0].id);

    if(!studentId){
        console.error("Error: Student not found with faculty number:", studentFacultyNumber);
        return res.status(404).send({ error: "Student not found in database." });
    }

    var joined_at_raw = req.body.joined_at;
    var left_at_raw = req.body.left_at;

    if(joined_at_raw == null || left_at_raw == null){
        console.error("This student has not attended the class: ", studentFacultyNumber);
        return res.status(400).send({ error: `${studentFacultyNumber} has not been marked as attended.` });
    }

    // Format timestamps in Bulgarian timezone (Europe/Sofia)
    const dateTimeBG = new Intl.DateTimeFormat('bg-BG', {
        timeZone: 'Europe/Sofia',
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
    });

    const joinedAtDate = new Date(joined_at_raw);
    const leftAtDate = new Date(left_at_raw);

    var joined_at = dateTimeBG.format(joinedAtDate);
    var left_at = dateTimeBG.format(leftAtDate);
    
    console.log("joined_at timestamp:", joined_at);
    console.log("left_at timestamp:", left_at);

    const sql = `INSERT INTO attendance_timestamps (class_id, student_id, joined_at, left_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`;

    const result  = await pool.query(sql, [classId, studentId, joined_at, left_at]);

    console.log("Student timestamps saved successfully for student:", studentId);
    
    return res.send({
        message: "Student timestamps saved"
    });

});



app.get("/get_student_attendance_count", async (req, res) => {
    logRequestStart(req);

    var classId = req.query.class_id;
    var studentId = req.query.student_id;
    var facultyNumber = req.query.faculty_number;

    console.log("classId:", classId, "studentId:", studentId, "facultyNumber:", facultyNumber);

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
        console.log("[ATTENDANCE COUNT] Resolving student by faculty_number:", resolveFacultyNumber);
        const facNorm = normalize(resolveFacultyNumber);
        const facHash = hashForLookup(facNorm);
        const studentLookup = await pool.query(
            "SELECT id FROM students WHERE faculty_number_hash = $1",
            [facHash]
        );
        console.log("[ATTENDANCE COUNT] studentLookup.rows:", studentLookup.rows);
        if (studentLookup.rows.length === 0) {
            return res.status(404).send({ error: "Student not found" });
        }
        studentIdNum = studentLookup.rows[0].id;
    } else {
        return res.status(400).send({ error: "student_id or faculty_number is required" });
    }
    console.log("[ATTENDANCE COUNT] Using studentId:", studentIdNum);

    const sqlForStudentAttendance = `
        SELECT COALESCE((SELECT count FROM attendances WHERE class_id = $1 AND student_id = $2), 0) AS count
    `;

    const sqlForTotalCompletedClasses = `
        SELECT COALESCE(completed_classes_count, 0) AS completed_classes_count FROM classes WHERE id = $1
    `;

    const result  = await pool.query(sqlForStudentAttendance, [classIdNum, studentIdNum]);
    const result2 = await pool.query(sqlForTotalCompletedClasses, [classIdNum]);

    console.log('Query result:', result.rows);
    console.log('Query result 2:', result2.rows);

    const attendanceCount = Number(result.rows[0]?.count ?? 0);
    const totalCompletedClassesCount = Number(result2.rows[0]?.completed_classes_count ?? 0);
    

    console.log("Attendance count:", attendanceCount);
    console.log("Total completed classes count:", totalCompletedClassesCount);
    
    return res.send({
        message: "Student attendance count fetched",
        attendance_count: attendanceCount,
        total_completed_classes_count: totalCompletedClassesCount
    });

});



app.post("/update_completed_classes_count", requireTeacherAuth, async (req, res) => {
    logRequestStart(req);
    
    var classId = req.body.class_id;

    console.log("classId:", classId);

    const sql = `UPDATE classes SET completed_classes_count = completed_classes_count + 1 WHERE id = $1 AND teacher_id = $2`;
    const result  = await pool.query(sql, [classId, req.authTeacherId]);
    if (result.rowCount === 0) {
        return res.status(404).send({ error: "Class not found for this teacher" });
    }

    console.log('Query result:', result.rows);
    
    return res.send({
        message: "Completed classes count updated"
    });

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
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));


