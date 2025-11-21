const express = require("express");
const crypto = require("crypto");

function pad6(n) {
  return n.toString().padStart(6, "0");
}

function generateVerificationCode() {
  const n = crypto.randomInt(0, 1000000);
  return pad6(n);
}

async function ensureSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_verification_codes (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INT NOT NULL DEFAULT 0,
      resend_count INT NOT NULL DEFAULT 0,
      last_sent_at TIMESTAMPTZ NOT NULL,
      verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ev_email ON email_verification_codes(email);`);
  await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;`);
}

function validateEmail(email) {
  if (!email || typeof email !== "string") return false;
  const e = email.trim();
  if (!e) return false;
  return /.+@.+\..+/.test(e);
}

async function sendVerificationEmail(email, code, options = {}) {
  const { customSender } = options;
  if (typeof customSender === "function") {
    return customSender(email, code);
  }
  console.log(`Email verification code for ${email}: ${code}`);
  return { ok: true };
}

function secondsUntil(date) {
  const ms = date.getTime() - Date.now();
  return Math.max(0, Math.ceil(ms / 1000));
}

function createEmailVerificationRouter(pool, config = {}) {
  const router = express.Router();
  const cooldownSeconds = Number(config.cooldownSeconds ?? 60);
  const codeTTLMinutes = Number(config.codeTTLMinutes ?? 10);
  const maxVerifyAttempts = Number(config.maxVerifyAttempts ?? 5);
  const maxResends = Number(config.maxResends ?? 3);

  router.post("/sendVerificationCode", async (req, res) => {
    try {
      const rawEmail = (req.body && req.body.email) || "";
      const email = String(rawEmail).trim().toLowerCase();
      if (!validateEmail(email)) {
        return res.status(400).send({ ok: false, error: "invalid_email" });
      }

      const { rows } = await pool.query(
        `SELECT * FROM email_verification_codes WHERE email = $1 AND verified = FALSE ORDER BY created_at DESC LIMIT 1`,
        [email]
      );
      const existing = rows[0];
      const now = new Date();
      const ttlMs = codeTTLMinutes * 60 * 1000;
      const cooldownMs = cooldownSeconds * 1000;

      if (existing) {
        const lastSentAt = new Date(existing.last_sent_at);
        const expiresAt = new Date(existing.expires_at);
        const inCooldown = now.getTime() - lastSentAt.getTime() < cooldownMs;
        const notExpired = now.getTime() < expiresAt.getTime();
        if (inCooldown) {
          const retryAfter = Math.ceil((cooldownMs - (now.getTime() - lastSentAt.getTime())) / 1000);
          return res
            .status(429)
            .send({ ok: false, error: "cooldown", retryAfterSeconds: retryAfter });
        }
        if (notExpired && existing.resend_count >= maxResends) {
          return res.status(429).send({ ok: false, error: "resend_limit" });
        }
      }

      const code = generateVerificationCode();
      const expiresAt = new Date(Date.now() + ttlMs);
      const lastSentAt = now;

      if (existing && new Date(existing.expires_at).getTime() > now.getTime()) {
        await pool.query(
          `UPDATE email_verification_codes
           SET code = $2, expires_at = $3, last_sent_at = $4,
               resend_count = CASE WHEN resend_count IS NULL THEN 1 ELSE resend_count + 1 END
           WHERE id = $1`,
          [existing.id, code, expiresAt.toISOString(), lastSentAt.toISOString()]
        );
      } else {
        await pool.query(
          `INSERT INTO email_verification_codes (email, code, expires_at, attempts, resend_count, last_sent_at, verified)
           VALUES ($1, $2, $3, 0, 0, $4, FALSE)`,
          [email, code, expiresAt.toISOString(), lastSentAt.toISOString()]
        );
      }

      await sendVerificationEmail(email, code, { customSender: config.customSender });
      return res.send({ ok: true, message: "code_sent", expiresInSeconds: secondsUntil(expiresAt) });
    } catch (err) {
      console.error("sendVerificationCode error", err);
      return res.status(500).send({ ok: false, error: "server_error" });
    }
  });

  router.post("/verifyEmailCode", async (req, res) => {
    try {
      const rawEmail = (req.body && req.body.email) || "";
      const rawCode = (req.body && req.body.code) || "";
      const email = String(rawEmail).trim().toLowerCase();
      const code = String(rawCode).trim();
      if (!validateEmail(email) || !/^\d{6}$/.test(code)) {
        return res.status(400).send({ ok: false, error: "invalid_payload" });
      }

      const { rows } = await pool.query(
        `SELECT * FROM email_verification_codes WHERE email = $1 AND verified = FALSE ORDER BY created_at DESC LIMIT 1`,
        [email]
      );
      const record = rows[0];
      if (!record) {
        return res.status(400).send({ ok: false, error: "invalid_code" });
      }

      const now = new Date();
      const expiresAt = new Date(record.expires_at);
      if (now.getTime() > expiresAt.getTime()) {
        return res.status(400).send({ ok: false, error: "expired" });
      }

      if (record.attempts >= maxVerifyAttempts) {
        return res.status(429).send({ ok: false, error: "too_many_attempts" });
      }

      if (record.code !== code) {
        const attempts = (record.attempts || 0) + 1;
        await pool.query(
          `UPDATE email_verification_codes SET attempts = $2 WHERE id = $1`,
          [record.id, attempts]
        );
        const remaining = Math.max(0, maxVerifyAttempts - attempts);
        return res.status(400).send({ ok: false, error: "invalid_code", attemptsRemaining: remaining });
      }

      await pool.query(`UPDATE email_verification_codes SET verified = TRUE WHERE id = $1`, [record.id]);
      await pool.query(`UPDATE students SET email_verified = TRUE WHERE email = $1`, [email]);

      return res.send({ ok: true, message: "email_verified" });
    } catch (err) {
      console.error("verifyEmailCode error", err);
      return res.status(500).send({ ok: false, error: "server_error" });
    }
  });

  return router;
}

module.exports = {
  createEmailVerificationRouter,
  ensureSchema,
  generateVerificationCode,
  sendVerificationEmail
};
