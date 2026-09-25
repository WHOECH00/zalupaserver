const express = require('express');
const { Pool }  = require('pg');
const crypto    = require('crypto');

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ══════════════════════════════════════════════════════════════════════════════
//  DB INIT
// ══════════════════════════════════════════════════════════════════════════════

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        key          TEXT PRIMARY KEY,
        owner        TEXT NOT NULL,
        hwid         TEXT,
        token        TEXT,
        expires_at   TIMESTAMPTZ NOT NULL,
        seats_total  INT  NOT NULL DEFAULT 1,
        seats_used   INT  NOT NULL DEFAULT 0,
        revoked      BOOL NOT NULL DEFAULT FALSE,
        is_admin     BOOL NOT NULL DEFAULT FALSE,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_events (
        id          SERIAL PRIMARY KEY,
        license_key TEXT NOT NULL,
        hwid        TEXT,
        ip_address  TEXT,
        os_info     TEXT,
        action      TEXT NOT NULL,
        data        JSONB NOT NULL DEFAULT '{}',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_telemetry (
        license_key TEXT PRIMARY KEY,
        hwid        TEXT,
        ip_address  TEXT,
        os_info     TEXT,
        os_name     TEXT,
        os_version  TEXT,
        hostname    TEXT,
        app_version TEXT,
        last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS client_commands (
        id          SERIAL PRIMARY KEY,
        license_key TEXT NOT NULL,
        command     TEXT NOT NULL,
        payload     JSONB NOT NULL DEFAULT '{}',
        executed    BOOL NOT NULL DEFAULT FALSE,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    // backward-compat patches
    await pool.query(`ALTER TABLE licenses      ADD COLUMN IF NOT EXISTS is_admin BOOL DEFAULT FALSE`).catch(() => {});
    await pool.query(`ALTER TABLE user_events   ADD COLUMN IF NOT EXISTS os_info  TEXT`).catch(() => {});
    await pool.query(`ALTER TABLE user_telemetry ADD COLUMN IF NOT EXISTS os_info TEXT`).catch(() => {});

    console.log('[DB] ready');
  } catch (err) {
    console.error('[DB] init error:', err);
    process.exit(1);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════════════════════

const HMAC_SECRET   = process.env.HMAC_SECRET;
const REPLAY_WINDOW = 300; // 5 минут — достаточно для защиты от replay

function verifyRequest(body) {
  const { ts, sig, ...payload } = body;
  if (!ts || !sig) return false;
  if (Math.abs(Date.now() / 1000 - parseInt(ts)) > REPLAY_WINDOW) return false;
  const msg      = ts + '|' + JSON.stringify(payload, Object.keys(payload).sort());
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(msg).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

function newToken()    { return crypto.randomBytes(48).toString('hex'); }
function randChunk()   { return crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 5); }
function getIP(req)    {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.headers['x-real-ip']
    || req.socket?.remoteAddress
    || 'unknown';
}

// Проверить pending commands для ключа и пометить их выполненными
async function popCommands(licenseKey) {
  const cmds = await pool.query(
    `SELECT id, command, payload FROM client_commands
     WHERE license_key = $1 AND executed = FALSE
     ORDER BY id ASC LIMIT 10`,
    [licenseKey]
  );
  if (cmds.rows.length > 0) {
    await pool.query(
      `UPDATE client_commands SET executed = TRUE WHERE id = ANY($1)`,
      [cmds.rows.map(c => c.id)]
    );
  }
  return cmds.rows.map(c => ({ command: c.command, payload: c.payload }));
}

// Удалить все данные лицензии
async function deleteLicense(key) {
  await pool.query(`DELETE FROM user_events     WHERE license_key = $1`, [key]);
  await pool.query(`DELETE FROM user_telemetry  WHERE license_key = $1`, [key]);
  await pool.query(`DELETE FROM client_commands WHERE license_key = $1`, [key]);
  await pool.query(`DELETE FROM licenses        WHERE key = $1`,         [key]);
}

// ── Auth middlewares ──────────────────────────────────────────────────────────

// Для новых вызовов: x-admin-key = лицензионный ключ с is_admin=TRUE
// Legacy: x-admin-secret = ADMIN_SECRET из env
async function requireAdmin(req, res, next) {
  // Legacy header
  const secret = req.headers['x-admin-secret'];
  if (secret) {
    if (secret === process.env.ADMIN_SECRET) return next();
    return res.status(403).json({ status: 'forbidden' });
  }
  // New: license-based admin
  const key = req.headers['x-admin-key'];
  if (!key) return res.status(403).json({ status: 'forbidden', message: 'No auth header' });
  const r = await pool.query(
    `SELECT is_admin, revoked FROM licenses WHERE key = $1`, [key]
  );
  if (!r.rows.length || r.rows[0].revoked || !r.rows[0].is_admin)
    return res.status(403).json({ status: 'forbidden' });
  next();
}

function requireEnvSecret(req, res, next) {
  if (req.headers['x-admin-secret'] !== process.env.ADMIN_SECRET)
    return res.status(403).json({ status: 'forbidden' });
  next();
}

// ══════════════════════════════════════════════════════════════════════════════
//  LICENSE API  (вызывается клиентом, все запросы подписаны HMAC)
// ══════════════════════════════════════════════════════════════════════════════

// ── ACTIVATE ─────────────────────────────────────────────────────────────────
app.post('/api/license/activate', async (req, res) => {
  if (!verifyRequest(req.body))
    return res.status(403).json({ status: 'error', message: 'Invalid signature' });

  const { key, hwid, os_info } = req.body;
  if (!key || !hwid)
    return res.status(400).json({ status: 'error', message: 'Missing fields' });

  const r = await pool.query(`SELECT * FROM licenses WHERE key = $1`, [key]);
  if (!r.rows.length) return res.status(404).json({ status: 'not_found' });

  const lic = r.rows[0];
  if (lic.revoked)                          return res.status(403).json({ status: 'revoked' });
  if (new Date(lic.expires_at) < new Date()) return res.status(403).json({ status: 'expired' });

  // Если ключ уже привязан к другому HWID и слоты заполнены — отказ
  if (lic.hwid && lic.hwid !== hwid && lic.seats_used >= lic.seats_total)
    return res.status(403).json({ status: 'hwid_mismatch' });
  if (!lic.hwid && lic.seats_used >= lic.seats_total)
    return res.status(403).json({ status: 'seats_full' });

  const token = newToken();
  const ip    = getIP(req);

  await pool.query(
    `UPDATE licenses SET hwid=$1, token=$2, seats_used=GREATEST(seats_used,1) WHERE key=$3`,
    [hwid, token, key]
  );

  await pool.query(
    `INSERT INTO user_events (license_key, hwid, ip_address, os_info, action, data)
     VALUES ($1,$2,$3,$4,'activate',$5)`,
    [key, hwid, ip, os_info || null, JSON.stringify({ owner: lic.owner })]
  );

  const commands = await popCommands(key);

  return res.json({
    status:      'ok',
    token,
    owner:       lic.owner,
    expires_at:  lic.expires_at,
    seats_left:  lic.seats_total - lic.seats_used - 1,
    is_admin:    lic.is_admin,
    admin_secret: lic.is_admin ? process.env.ADMIN_SECRET : undefined,
    commands,
  });
});

// ── VALIDATE ─────────────────────────────────────────────────────────────────
// Вызывается фоновым вотчером каждые 30 секунд.
// При отзыве/удалении лицензии сервер вернёт статус != ok →
// клиент немедленно выкинет пользователя.
app.post('/api/license/validate', async (req, res) => {
  if (!verifyRequest(req.body))
    return res.status(403).json({ status: 'error', message: 'Invalid signature' });

  const { key, hwid, token, os_info, app_version } = req.body;
  if (!key || !hwid || !token)
    return res.status(400).json({ status: 'error', message: 'Missing fields' });

  const r = await pool.query(`SELECT * FROM licenses WHERE key = $1`, [key]);
  if (!r.rows.length) return res.status(404).json({ status: 'not_found' });

  const lic = r.rows[0];
  if (lic.revoked)                          return res.status(403).json({ status: 'revoked' });
  if (new Date(lic.expires_at) < new Date()) return res.status(403).json({ status: 'expired' });
  if (lic.hwid !== hwid)                    return res.status(403).json({ status: 'hwid_mismatch' });
  if (lic.token !== token)                  return res.status(403).json({ status: 'revoked' });

  const newTok = newToken();
  const ip     = getIP(req);

  await pool.query(`UPDATE licenses SET token=$1 WHERE key=$2`, [newTok, key]);

  // Обновляем телеметрию (upsert)
  await pool.query(
    `INSERT INTO user_telemetry (license_key, hwid, ip_address, os_info, app_version, last_seen, first_seen)
     VALUES ($1,$2,$3,$4,$5,NOW(),NOW())
     ON CONFLICT (license_key) DO UPDATE SET
       hwid=EXCLUDED.hwid, ip_address=EXCLUDED.ip_address,
       os_info=EXCLUDED.os_info, app_version=EXCLUDED.app_version, last_seen=NOW()`,
    [key, hwid, ip, os_info || null, app_version || null]
  );

  const commands = await popCommands(key);

  return res.json({
    status:      'ok',
    token:       newTok,
    owner:       lic.owner,
    expires_at:  lic.expires_at,
    is_admin:    lic.is_admin,
    admin_secret: lic.is_admin ? process.env.ADMIN_SECRET : undefined,
    commands,
  });
});

// ── DEACTIVATE ────────────────────────────────────────────────────────────────
app.post('/api/license/deactivate', async (req, res) => {
  if (!verifyRequest(req.body))
    return res.status(403).json({ status: 'error', message: 'Invalid signature' });

  const { key, hwid, token } = req.body;
  const r = await pool.query(
    `SELECT key FROM licenses WHERE key=$1 AND hwid=$2 AND token=$3`,
    [key, hwid, token]
  );
  if (!r.rows.length) return res.status(403).json({ status: 'not_found' });

  await pool.query(
    `UPDATE licenses SET hwid=NULL, token=NULL, seats_used=GREATEST(seats_used-1,0) WHERE key=$1`,
    [key]
  );
  return res.json({ status: 'ok' });
});

// ── EVENT (лог действий клиента) ──────────────────────────────────────────────
app.post('/api/license/event', async (req, res) => {
  if (!verifyRequest(req.body)) return res.status(403).json({ status: 'error' });
  const { key, hwid, action, data } = req.body;
  if (!key || !action) return res.status(400).json({ status: 'error' });
  await pool.query(
    `INSERT INTO user_events (license_key, hwid, ip_address, action, data) VALUES ($1,$2,$3,$4,$5)`,
    [key, hwid, getIP(req), action, JSON.stringify(data || {})]
  );
  return res.json({ status: 'ok' });
});

// Алиас для совместимости
app.post('/api/telemetry/event', (req, res) => res.redirect(307, '/api/license/event'));

// ══════════════════════════════════════════════════════════════════════════════
//  ADMIN API
// ══════════════════════════════════════════════════════════════════════════════

// Проверка что ключ является admin (вызывается при логине в админку)
app.post('/api/admin/verify', async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ status: 'error' });
  const r = await pool.query(
    `SELECT is_admin, revoked, owner FROM licenses WHERE key = $1`, [key]
  );
  if (!r.rows.length || r.rows[0].revoked || !r.rows[0].is_admin)
    return res.status(403).json({ status: 'forbidden' });
  return res.json({ status: 'ok', owner: r.rows[0].owner });
});

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
// Возвращает всё что нужно клиенту за один запрос:
//   { stats, online_count, online[], licenses[], events[], event_stats[] }
app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  const [activeQ, revokedQ, onlineQ, licensesQ, eventsQ, eventStatsQ] = await Promise.all([
    pool.query(`
      SELECT COUNT(*)::int AS cnt FROM licenses
      WHERE is_admin=FALSE AND revoked=FALSE AND expires_at > NOW()
    `),
    pool.query(`SELECT COUNT(*)::int AS cnt FROM licenses WHERE revoked=TRUE`),
    pool.query(`
      SELECT t.license_key, l.owner, t.ip_address,
             t.os_info, t.app_version, t.last_seen
      FROM user_telemetry t
      JOIN licenses l ON l.key = t.license_key
      WHERE t.last_seen > NOW() - INTERVAL '10 minutes'
      ORDER BY t.last_seen DESC
    `),
    pool.query(`
      SELECT l.key, l.owner, l.hwid, l.expires_at, l.revoked, l.is_admin,
             l.seats_total, l.seats_used, l.created_at,
             t.ip_address, t.os_info, t.os_name, t.os_version,
             t.hostname, t.app_version, t.last_seen, t.first_seen
      FROM licenses l
      LEFT JOIN user_telemetry t ON l.key = t.license_key
      WHERE l.is_admin = FALSE
      ORDER BY t.last_seen DESC NULLS LAST, l.created_at DESC
    `),
    pool.query(`
      SELECT e.id, e.created_at, e.license_key, e.hwid,
             e.ip_address, e.action, e.data, l.owner
      FROM user_events e
      LEFT JOIN licenses l ON l.key = e.license_key
      ORDER BY e.created_at DESC
      LIMIT 500
    `),
    pool.query(`
      SELECT action, COUNT(*)::int AS count
      FROM user_events
      WHERE created_at > NOW() - INTERVAL '24 hours'
      GROUP BY action ORDER BY count DESC
    `),
  ]);

  return res.json({
    stats: {
      active_licenses:  activeQ.rows[0].cnt,
      revoked_licenses: revokedQ.rows[0].cnt,
    },
    online_count: onlineQ.rows.length,
    online:       onlineQ.rows,
    licenses:     licensesQ.rows,
    events:       eventsQ.rows,
    event_stats:  eventStatsQ.rows,
  });
});

// ── STATS (отдельно, для совместимости) ──────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [total, online, events_today, revoked] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int AS c FROM licenses WHERE is_admin=FALSE`),
    pool.query(`SELECT COUNT(*)::int AS c FROM user_telemetry WHERE last_seen > NOW() - INTERVAL '10 minutes'`),
    pool.query(`SELECT COUNT(*)::int AS c FROM user_events WHERE created_at > NOW() - INTERVAL '24 hours'`),
    pool.query(`SELECT COUNT(*)::int AS c FROM licenses WHERE revoked=TRUE`),
  ]);
  return res.json({
    total_licenses: total.rows[0].c,
    online_now:     online.rows[0].c,
    events_today:   events_today.rows[0].c,
    revoked:        revoked.rows[0].c,
  });
});

// ── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const r = await pool.query(
    `SELECT key, owner, hwid, expires_at, revoked, seats_total, seats_used, created_at
     FROM licenses WHERE is_admin = FALSE ORDER BY created_at DESC`
  );
  return res.json(r.rows);
});

// ── USER (один) ───────────────────────────────────────────────────────────────
app.get('/api/admin/user/:key', requireAdmin, async (req, res) => {
  const r = await pool.query(`
    SELECT l.key, l.owner, l.hwid, l.expires_at, l.revoked, l.is_admin,
           l.seats_total, l.seats_used, l.created_at,
           t.ip_address, t.os_info, t.os_name, t.os_version,
           t.hostname, t.app_version, t.last_seen, t.first_seen
    FROM licenses l
    LEFT JOIN user_telemetry t ON l.key = t.license_key
    WHERE l.key = $1
  `, [req.params.key]);
  if (!r.rows.length) return res.status(404).json({ status: 'not_found' });
  return res.json(r.rows[0]);
});

// ── EVENTS ────────────────────────────────────────────────────────────────────
app.get('/api/admin/events', requireAdmin, async (req, res) => {
  const { key, action, limit = 500 } = req.query;
  let   q      = `SELECT e.*, l.owner FROM user_events e LEFT JOIN licenses l ON l.key=e.license_key WHERE 1=1`;
  const params = [];
  if (key)    { params.push(key);    q += ` AND e.license_key=$${params.length}`; }
  if (action) { params.push(action); q += ` AND e.action=$${params.length}`; }
  params.push(Math.min(parseInt(limit) || 500, 1000));
  q += ` ORDER BY e.created_at DESC LIMIT $${params.length}`;
  return res.json((await pool.query(q, params)).rows);
});

// ── REVOKE / UNREVOKE ─────────────────────────────────────────────────────────
app.post('/api/admin/revoke', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ status: 'error' });
  // Отзываем: сбрасываем токен — при следующей валидации клиент получит 'revoked'
  await pool.query(
    `UPDATE licenses SET revoked=TRUE, token=NULL WHERE key=$1`, [key]
  );
  return res.json({ status: 'ok' });
});

app.post('/api/admin/unrevoke', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ status: 'error' });
  await pool.query(`UPDATE licenses SET revoked=FALSE WHERE key=$1`, [key]);
  return res.json({ status: 'ok' });
});

// ── RESET HWID ────────────────────────────────────────────────────────────────
app.post('/api/admin/reset-hwid', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ status: 'error' });
  await pool.query(
    `UPDATE licenses SET hwid=NULL, token=NULL, seats_used=0 WHERE key=$1`, [key]
  );
  return res.json({ status: 'ok' });
});

// ── COMMANDS (send-command / command — оба работают) ─────────────────────────
async function sendCommand(key, command, payload = {}) {
  await pool.query(
    `INSERT INTO client_commands (license_key, command, payload) VALUES ($1,$2,$3)`,
    [key, command, JSON.stringify(payload)]
  );
}

app.post('/api/admin/command',      requireAdmin, async (req, res) => {
  const { key, command, payload = {} } = req.body;
  if (!key || !command) return res.status(400).json({ status: 'error' });
  await sendCommand(key, command, payload);
  return res.json({ status: 'ok' });
});

app.post('/api/admin/send-command', requireAdmin, async (req, res) => {
  const { key, command, payload = {} } = req.body;
  if (!key || !command) return res.status(400).json({ status: 'error' });
  await sendCommand(key, command, payload);
  return res.json({ status: 'ok' });
});

// ── DELETE ────────────────────────────────────────────────────────────────────
app.delete('/api/admin/delete-license', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ status: 'error' });
  await deleteLicense(key);
  return res.json({ status: 'ok' });
});

// Алиас — клиент вызывает DELETE /api/admin/delete-key/:key
app.delete('/api/admin/delete-key/:key', requireAdmin, async (req, res) => {
  await deleteLicense(req.params.key);
  return res.json({ status: 'ok' });
});

// ── EXTEND (продлить лицензию) ────────────────────────────────────────────────
app.post('/api/admin/extend', requireAdmin, async (req, res) => {
  const { key, days = 30 } = req.body;
  if (!key) return res.status(400).json({ status: 'error' });
  await pool.query(
    `UPDATE licenses SET expires_at = expires_at + ($1 || ' days')::interval WHERE key = $2`,
    [parseInt(days), key]
  );
  const r = await pool.query(`SELECT expires_at FROM licenses WHERE key=$1`, [key]);
  return res.json({ status: 'ok', expires_at: r.rows[0]?.expires_at });
});

// ══════════════════════════════════════════════════════════════════════════════
//  LEGACY ADMIN API  (x-admin-secret, обратная совместимость)
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/admin/create-key', requireEnvSecret, async (req, res) => {
  const { owner, days = 365, seats = 1, is_admin = false } = req.body;
  if (!owner) return res.status(400).json({ error: 'owner required' });
  const key     = `SIMPR-${randChunk()}-${randChunk()}-${randChunk()}-${randChunk()}`;
  const expires = new Date();
  expires.setDate(expires.getDate() + parseInt(days));
  await pool.query(
    `INSERT INTO licenses (key, owner, expires_at, seats_total, is_admin) VALUES ($1,$2,$3,$4,$5)`,
    [key, owner, expires.toISOString(), seats, is_admin]
  );
  return res.json({ status: 'ok', key, owner, expires_at: expires.toISOString(), is_admin });
});

app.get('/api/admin/keys', requireEnvSecret, async (req, res) => {
  const r = await pool.query(
    `SELECT key, owner, hwid, expires_at, revoked, is_admin, seats_total, seats_used, created_at
     FROM licenses ORDER BY created_at DESC`
  );
  return res.json(r.rows);
});

app.post('/api/admin/revoke-secret', requireEnvSecret, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ status: 'error' });
  await pool.query(`UPDATE licenses SET revoked=TRUE, token=NULL WHERE key=$1`, [key]);
  return res.json({ status: 'ok' });
});

// ══════════════════════════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════════════════════════

const PORT = process.env.PORT || 3000;
