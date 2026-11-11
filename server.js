require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Return {"error": "..."} if someone sends invalid JSON
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }
  next();
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ============================================================================
// Helper Functions
// ============================================================================
function isValidEmail(email) {
  if (typeof email !== 'string' || email.length > 254) return false;
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@.]{2,}$/;
  if (!regex.test(email)) return false;
  const [local, domain] = email.split('@');
  if (!local || !domain) return false;
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) return false;
  return true;
}

function hashRequestBody(body) {
  if (!body || typeof body !== 'object') return JSON.stringify(body);
  const canonical = {};
  Object.keys(body).sort().forEach((k) => {
    canonical[k] = body[k];
  });
  return JSON.stringify(canonical);
}

function formatBooking(row) {
  return {
    id: row.id,
    slot_id: row.slot_id,
    name: row.name,
    email: row.email,
    status: row.status,
    created_at: new Date(row.created_at).toISOString()
  };
}

// ============================================================================
// LEVEL 2: X-API-Key Authentication Middleware
// ============================================================================
const EXPECTED_API_KEY = (process.env.API_KEY || 'koya-secret-key-2026')
  .trim()
  .replace(/^["']|["']$/g, '');

const requireApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key']?.trim();
  if (!apiKey || apiKey !== EXPECTED_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized: missing or invalid X-API-Key' });
  }
  next();
};

// Helper route so our frontend webpage can automatically fill in the API Key
app.get('/config', (req, res) => {
  res.json({ apiKey: EXPECTED_API_KEY });
});
// ============================================================================
// POST /reset (Level 1 · Replace all slots and clear bookings)
// ============================================================================
app.post('/reset', requireApiKey, async (req, res) => {
  const slots = req.body?.slots;
  if (!Array.isArray(slots)) {
    return res.status(400).json({ error: 'slots array is required' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'TRUNCATE TABLE bookings, slots, idempotency_keys, rate_limits RESTART IDENTITY CASCADE'
    );

    for (const slot of slots) {
      await client.query(
        `INSERT INTO slots (id, provider, start_time, end_time, start_raw, end_raw)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          String(slot.id),
          String(slot.provider),
          slot.start,
          slot.end,
          String(slot.start),
          String(slot.end)
        ]
      );
    }

    await client.query('COMMIT');
    return res.status(200).json({ status: 'ok' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error in POST /reset:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// ============================================================================
// GET /slots (Level 1 · List slots, earliest start first)
// ============================================================================
app.get('/slots', requireApiKey, async (req, res) => {
  const provider = req.query.provider !== undefined ? String(req.query.provider) : null;

  try {
    const result = await pool.query(
      `SELECT 
         s.id,
         s.provider,
         s.start_raw AS start,
         s.end_raw AS end,
         CASE WHEN b.id IS NULL THEN TRUE ELSE FALSE END AS available
       FROM slots s
       LEFT JOIN bookings b ON s.id = b.slot_id AND b.status = 'confirmed'
       WHERE ($1::text IS NULL OR s.provider = $1)
       ORDER BY s.start_time ASC, s.id ASC`,
      [provider]
    );

    return res.status(200).json({ slots: result.rows });
  } catch (err) {
    console.error('Error in GET /slots:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================================
// POST /bookings (Levels 1–5 · Book a slot)
// ============================================================================
app.post('/bookings', requireApiKey, async (req, res) => {
  const rawBody = req.body || {};
  const rawSlotId = typeof rawBody.slot_id === 'string' ? rawBody.slot_id.trim() : '';
  const cleanName = typeof rawBody.name === 'string' ? rawBody.name.trim() : '';
  const cleanEmail = typeof rawBody.email === 'string' ? rawBody.email.trim().toLowerCase() : '';
  const idempotencyKey =
    typeof req.headers['idempotency-key'] === 'string' && req.headers['idempotency-key'].trim() !== ''
      ? req.headers['idempotency-key'].trim()
      : null;
  const bodyHash = hashRequestBody(rawBody);

  // --------------------------------------------------------------------------
  // LEVEL 5: Rate Limiting (Max 5 attempts per email per minute, failed included)
  // --------------------------------------------------------------------------
  const rateLimitKey = cleanEmail || '__missing_email__';
  const rlClient = await pool.connect();
  try {
    await rlClient.query('BEGIN');
    await rlClient.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`rl:${rateLimitKey}`]);

    const rlResult = await rlClient.query(
      `SELECT EXTRACT(EPOCH FROM (created_at + INTERVAL '60 seconds' - NOW())) AS seconds_left
       FROM rate_limits
       WHERE email = $1 AND created_at > NOW() - INTERVAL '60 seconds'
       ORDER BY created_at ASC`,
      [rateLimitKey]
    );

    if (rlResult.rows.length >= 5) {
      const oldestSecondsLeft = parseFloat(rlResult.rows[0].seconds_left);
      const retryAfter = Math.max(1, Math.min(60, Math.ceil(oldestSecondsLeft)));
      await rlClient.query('COMMIT');
      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({ error: 'Too many attempts for this email' });
    }

    await rlClient.query('INSERT INTO rate_limits (email) VALUES ($1)', [rateLimitKey]);
    await rlClient.query('COMMIT');
  } catch (err) {
    await rlClient.query('ROLLBACK');
    console.error('Rate limit error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    rlClient.release();
  }

  // --------------------------------------------------------------------------
  // LEVEL 1, 2, 3, 4: Idempotency, Validation, Concurrency Lock, and Booking
  // --------------------------------------------------------------------------
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // LEVEL 4: Check Idempotency-Key
    if (idempotencyKey) {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`idem:${idempotencyKey}`]);

      const existingKey = await client.query(
        'SELECT body_hash, status_code, response_body FROM idempotency_keys WHERE key = $1',
        [idempotencyKey]
      );

      if (existingKey.rows.length > 0) {
        const record = existingKey.rows[0];
        await client.query('COMMIT');
        if (record.body_hash !== bodyHash) {
          return res.status(422).json({ error: 'Idempotency-Key reused with a different body' });
        }
        return res.status(record.status_code).json(record.response_body);
      }
    }

    const respondWithIdempotency = async (statusCode, payload, shouldCommitBooking = false) => {
      if (!shouldCommitBooking) {
        await client.query('ROLLBACK');
        if (idempotencyKey) {
          await client.query('BEGIN');
          await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`idem:${idempotencyKey}`]);
          await client.query(
            `INSERT INTO idempotency_keys (key, body_hash, status_code, response_body)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (key) DO NOTHING`,
            [idempotencyKey, bodyHash, statusCode, payload]
          );
          await client.query('COMMIT');
        }
        return res.status(statusCode).json(payload);
      } else {
        if (idempotencyKey) {
          await client.query(
            `INSERT INTO idempotency_keys (key, body_hash, status_code, response_body)
             VALUES ($1, $2, $3, $4)`,
            [idempotencyKey, bodyHash, statusCode, payload]
          );
        }
        await client.query('COMMIT');
        return res.status(statusCode).json(payload);
      }
    };

    // LEVEL 2: Validate fields
    if (!rawSlotId || !cleanName || !cleanEmail || !isValidEmail(cleanEmail)) {
      return await respondWithIdempotency(400, {
        error: 'slot_id, name, and a valid email are required'
      });
    }

    // LEVEL 3: Lock the slot row FOR UPDATE so concurrent requests queue safely
    const slotResult = await client.query(
      'SELECT id, start_time FROM slots WHERE id = $1 FOR UPDATE',
      [rawSlotId]
    );

    // LEVEL 2: 404 if slot doesn't exist
    if (slotResult.rows.length === 0) {
      return await respondWithIdempotency(404, { error: 'slot not found' });
    }

    const slot = slotResult.rows[0];

    // LEVEL 2: 400 if the slot has already started
    if (new Date(slot.start_time).getTime() <= Date.now()) {
      return await respondWithIdempotency(400, { error: 'slot has already started' });
    }

    // LEVEL 3: 409 if the slot is already booked
    const existingBooking = await client.query(
      `SELECT id FROM bookings WHERE slot_id = $1 AND status = 'confirmed'`,
      [rawSlotId]
    );

    if (existingBooking.rows.length > 0) {
      return await respondWithIdempotency(409, { error: 'slot already booked' });
    }

    // LEVEL 1: Insert booking
    const insertResult = await client.query(
      `INSERT INTO bookings (slot_id, name, email, status)
       VALUES ($1, $2, $3, 'confirmed')
       RETURNING id, slot_id, name, email, status, created_at`,
      [rawSlotId, cleanName, cleanEmail]
    );

    const createdBooking = formatBooking(insertResult.rows[0]);
    return await respondWithIdempotency(201, createdBooking, true);
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') {
      return res.status(409).json({ error: 'slot already booked' });
    }
    console.error('Error in POST /bookings:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// ============================================================================
// GET /bookings (Level 4 · List a person's bookings, cursor pagination)
// ============================================================================
app.get('/bookings', requireApiKey, async (req, res) => {
  const rawEmail = req.query.email;
  if (!rawEmail || typeof rawEmail !== 'string' || rawEmail.trim() === '') {
    return res.status(400).json({ error: 'email query parameter is required' });
  }
  const email = rawEmail.trim().toLowerCase();

  let limit = 10;
  if (req.query.limit !== undefined) {
    const limitStr = String(req.query.limit);
    if (!/^\d+$/.test(limitStr)) {
      return res.status(400).json({ error: 'limit must be an integer between 1 and 50' });
    }
    limit = parseInt(limitStr, 10);
    if (limit < 1 || limit > 50) {
      return res.status(400).json({ error: 'limit must be between 1 and 50' });
    }
  }

  let cursorSeq = 0;
  if (req.query.cursor !== undefined && req.query.cursor !== '') {
    const cursorStr = String(req.query.cursor);
    if (!/^\d+$/.test(cursorStr)) {
      return res.status(400).json({ error: 'invalid cursor' });
    }
    cursorSeq = parseInt(cursorStr, 10);
  }

  try {
    const result = await pool.query(
      `SELECT id, slot_id, name, email, status, created_at, seq
       FROM bookings
       WHERE LOWER(email) = $1 AND seq > $2
       ORDER BY seq ASC
       LIMIT $3`,
      [email, cursorSeq, limit + 1]
    );

    const hasMore = result.rows.length > limit;
    const pageRows = hasMore ? result.rows.slice(0, limit) : result.rows;
    const next_cursor = hasMore ? String(pageRows[pageRows.length - 1].seq) : null;

    return res.status(200).json({
      bookings: pageRows.map(formatBooking),
      next_cursor
    });
  } catch (err) {
    console.error('Error in GET /bookings:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================================
// GET /bookings/:id (Level 1 · Get a booking)
// ============================================================================
app.get('/bookings/:id', requireApiKey, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'SELECT id, slot_id, name, email, status, created_at FROM bookings WHERE id::text = $1',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'booking not found' });
    }

    return res.status(200).json(formatBooking(result.rows[0]));
  } catch (err) {
    return res.status(404).json({ error: 'booking not found' });
  }
});

// ============================================================================
// DELETE /bookings/:id (Level 3 · Cancel a booking)
// ============================================================================
app.delete('/bookings/:id', requireApiKey, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const bookingResult = await client.query(
      'SELECT id, slot_id, name, email, status, created_at FROM bookings WHERE id::text = $1 FOR UPDATE',
      [id]
    );

    if (bookingResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'booking not found' });
    }

    const booking = bookingResult.rows[0];

    if (booking.status === 'cancelled') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'booking already cancelled' });
    }

    const updatedResult = await client.query(
      `UPDATE bookings
       SET status = 'cancelled'
       WHERE id = $1
       RETURNING id, slot_id, name, email, status, created_at`,
      [booking.id]
    );

    await client.query('COMMIT');
    return res.status(200).json(formatBooking(updatedResult.rows[0]));
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error in DELETE /bookings/:id:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// ============================================================================
// Auto-Initialize Database Tables & Seed Demo Slots on Startup
// ============================================================================
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS slots (
      id TEXT PRIMARY KEY,
      provider TEXT NOT NULL,
      start_time TIMESTAMPTZ NOT NULL,
      end_time TIMESTAMPTZ NOT NULL,
      start_raw TEXT NOT NULL,
      end_raw TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bookings (
      seq BIGSERIAL UNIQUE,
      id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
      slot_id TEXT NOT NULL REFERENCES slots(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'confirmed',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE UNIQUE INDEX IF NOT EXISTS unique_confirmed_slot 
    ON bookings (slot_id) 
    WHERE status = 'confirmed';

    CREATE TABLE IF NOT EXISTS idempotency_keys (
      key TEXT PRIMARY KEY,
      body_hash TEXT NOT NULL,
      status_code INTEGER NOT NULL,
      response_body JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS rate_limits (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_rate_limits_email_time 
    ON rate_limits (email, created_at);
  `);

  const { rows } = await pool.query('SELECT COUNT(*) FROM slots');
  if (parseInt(rows[0].count, 10) === 0) {
    const demoSlots = [
      { id: 's1', provider: 'Dr Ade', start: '2026-12-10T09:00:00Z', end: '2026-12-10T09:30:00Z' },
      { id: 's2', provider: 'Dr Ade', start: '2026-12-10T10:00:00Z', end: '2026-12-10T10:30:00Z' },
      { id: 's3', provider: 'Dr Bello', start: '2026-12-10T11:00:00Z', end: '2026-12-10T11:30:00Z' }
    ];
    for (const s of demoSlots) {
      await pool.query(
        `INSERT INTO slots (id, provider, start_time, end_time, start_raw, end_raw)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [s.id, s.provider, s.start, s.end, s.start, s.end]
      );
    }
    console.log('Seeded initial demo slots.');
  }
}

const PORT = process.env.PORT || 3000;
initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running at http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });