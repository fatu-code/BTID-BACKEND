require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const speakeasy = require('speakeasy');
const QRCode    = require('qrcode');
const multer   = require('multer');
const path     = require('path');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'btid-secret-2025';

// ── DATABASE ──────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ── SUPABASE STORAGE ──────────────────────────────────────────────
// Files are uploaded to the `btid-media` public bucket in Supabase Storage.
// Railway's filesystem is ephemeral (wipes on redeploy), so persistent
// storage MUST live outside the container. The service_role key bypasses
// bucket policies — backend-only, never expose to frontend.
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
  console.error('FATAL: SUPABASE_URL and SUPABASE_SERVICE_KEY env vars are required');
  process.exit(1);
}
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false } }
);
const STORAGE_BUCKET = 'btid-media';

// ── MIDDLEWARE ────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: false }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ── MULTER (memory storage) ───────────────────────────────────────
// Files stay in RAM as buffers; we push to Supabase Storage in the route.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB for videos
});
const uploadGeneral = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

// ── HELPERS ───────────────────────────────────────────────────────
function genId(prefix) {
  return prefix + '-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
}

/**
 * Upload an in-memory file buffer to Supabase Storage.
 * Returns the full public URL to save in the DB.
 * Throws on failure (caller should catch and 500).
 */
async function uploadToStorage(file, folder) {
  const ext = path.extname(file.originalname) || '';
  const objectPath = `${folder}/${uuidv4()}${ext}`;

  console.log(`[UPLOAD] Starting: ${objectPath} (${file.size} bytes, ${file.mimetype})`);

  const { data: uploadData, error } = await supabase.storage
    .from(STORAGE_BUCKET)
    .upload(objectPath, file.buffer, {
      contentType: file.mimetype,
      upsert: false,
    });

  if (error) {
    console.error(`[UPLOAD] FAILED for ${objectPath}:`, error);
    throw new Error('Storage upload failed: ' + error.message);
  }

  console.log(`[UPLOAD] Success:`, uploadData);

  const { data } = supabase.storage.from(STORAGE_BUCKET).getPublicUrl(objectPath);
  console.log(`[UPLOAD] Public URL: ${data.publicUrl}`);
  return { url: data.publicUrl, path: objectPath };
}

/**
 * Delete an object from Supabase Storage by its full public URL.
 * Safe: does nothing if URL doesn't match the expected format.
 */
async function deleteFromStorage(publicUrl) {
  if (!publicUrl || typeof publicUrl !== 'string') return;
  const marker = `/storage/v1/object/public/${STORAGE_BUCKET}/`;
  const idx = publicUrl.indexOf(marker);
  if (idx === -1) return;   // legacy /uploads/... url or external — ignore
  const objectPath = publicUrl.substring(idx + marker.length);
  await supabase.storage.from(STORAGE_BUCKET).remove([objectPath]);
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No token provided' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin' && req.user.role !== 'joshua') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ── HEALTH ────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ message: 'BTID Athlete Management System API', version: '1.1.0-supabase', status: 'running' });
});

// ── SEED ──────────────────────────────────────────────────────────
app.get('/api/seed', async (req, res) => {
  try {
    const hash = await bcrypt.hash('joshua123', 10);
    const scoutHash = await bcrypt.hash('scout123', 10);

    await pool.query(`
      INSERT INTO users (id, username, password, name, role, active_until)
      VALUES
        ('usr-joshua-001', 'joshua', $1, 'Joshua Muwanguzi', 'admin', NULL),
        ('usr-scout-001', 'scout1', $2, 'Scout Meddie', 'scout', NOW() + INTERVAL '30 days'),
        ('usr-scout-002', 'scout2', $2, 'Scout Peter', 'scout', NOW() + INTERVAL '7 days')
      ON CONFLICT (username) DO UPDATE SET
        password = EXCLUDED.password,
        name = EXCLUDED.name,
        role = EXCLUDED.role
    `, [hash, scoutHash]);

    res.json({
      message: 'BTID seeded successfully',
      users: [
        { username: 'joshua', password: 'joshua123', role: 'admin' },
        { username: 'scout1', password: 'scout123',  role: 'scout' },
        { username: 'scout2', password: 'scout123',  role: 'scout' },
      ]
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── LOGIN ──────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1', [username.trim().toLowerCase()]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid username or password' });

    // Check expiry for scouts
    if (user.role === 'scout' && user.active_until && new Date(user.active_until) < new Date()) {
      return res.status(403).json({ error: 'ACCOUNT_EXPIRED', message: 'Your access has expired. Contact Joshua.' });
    }

    // Check if 2FA is enabled
    if (user.totp_enabled && user.totp_secret) {
      // Issue a short-lived temp token for the 2FA step
      const tempToken = jwt.sign(
        { id: user.id, username: user.username, name: user.name, role: user.role },
        JWT_SECRET + '_2fa',
        { expiresIn: '5m' }
      );
      return res.json({ requires_2fa: true, temp_token: tempToken });
    }

    // Log the login
    await pool.query(
      `INSERT INTO login_log (id, user_id, username, name, role, ip, user_agent)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [genId('LOG'), user.id, user.username, user.name, user.role,
       req.ip || req.connection.remoteAddress,
       req.headers['user-agent'] || '']
    ).catch(() => {});

    // Update login count
    await pool.query(
      'UPDATE users SET login_count = COALESCE(login_count,0)+1, last_login = NOW() WHERE id = $1',
      [user.id]
    ).catch(() => {});

    const token = jwt.sign(
      { id: user.id, username: user.username, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { password: _, totp_secret: __, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── ACCOUNT UPDATE ────────────────────────────────────────────────
app.put('/api/account', authMiddleware, async (req, res) => {
  const { name, password } = req.body;
  try {
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET name=$1, password=$2 WHERE id=$3', [name, hash, req.user.id]);
    } else {
      await pool.query('UPDATE users SET name=$1 WHERE id=$2', [name, req.user.id]);
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── STATS ─────────────────────────────────────────────────────────
app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const [totalR, admittedR, eliminatedR, tryoutsR, tiersR] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM players'),
      pool.query("SELECT COUNT(*) FROM players WHERE outcome = 'admitted'"),
      pool.query("SELECT COUNT(*) FROM players WHERE outcome = 'eliminated'"),
      pool.query('SELECT COUNT(*) FROM tryout_batches'),
      pool.query(`SELECT tier, COUNT(*) as count FROM players WHERE tier IS NOT NULL GROUP BY tier`),
    ]);

    const tiers = {};
    tiersR.rows.forEach(r => { tiers[r.tier] = parseInt(r.count); });

    res.json({
      total:      parseInt(totalR.rows[0].count),
      admitted:   parseInt(admittedR.rows[0].count),
      eliminated: parseInt(eliminatedR.rows[0].count),
      tryouts:    parseInt(tryoutsR.rows[0].count),
      tier1:  tiers['1']   || 0,
      tier15: tiers['1.5'] || 0,
      tier2:  tiers['2']   || 0,
      tier3:  tiers['3']   || 0,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── REPORTS ───────────────────────────────────────────────────────
app.get('/api/reports', authMiddleware, async (req, res) => {
  const { batch_id, district, season } = req.query;
  try {
    let where = 'WHERE 1=1';
    const params = [];
    let i = 1;
    if (batch_id) { where += ` AND batch_id = $${i++}`; params.push(batch_id); }
    if (season)   { where += ` AND season = $${i++}`;    params.push(parseInt(season)); }
    if (district) { where += ` AND district = $${i++}`; params.push(district); }

    const r = await pool.query(`
      SELECT
        COUNT(*) as total,
        COUNT(CASE WHEN outcome='admitted' THEN 1 END) as admitted,
        COUNT(CASE WHEN outcome='eliminated' THEN 1 END) as eliminated
      FROM players ${where}`, params);

    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PLAYERS ───────────────────────────────────────────────────────
app.get('/api/players', authMiddleware, async (req, res) => {
  const { district, tier, outcome, batch_id, limit, sort, season } = req.query;
  try {
    let where = 'WHERE 1=1';
    const params = [];
    let i = 1;

    if (district) { where += ` AND district = $${i++}`; params.push(district); }
    if (tier)     { where += ` AND tier = $${i++}`;     params.push(tier); }
    if (outcome === 'pending') {
      where += ' AND outcome IS NULL';
    } else if (outcome) {
      where += ` AND outcome = $${i++}`; params.push(outcome);
    }
    if (batch_id) { where += ` AND batch_id = $${i++}`; params.push(batch_id); }
    if (season)   { where += ` AND season = $${i++}`;    params.push(parseInt(season)); }

    let orderBy = 'ORDER BY created_at DESC';
    if (sort === 'name')    orderBy = 'ORDER BY name ASC';
    else if (sort === 'tier') orderBy = 'ORDER BY tier ASC NULLS LAST';

    let query = `SELECT * FROM players ${where} ${orderBy}`;
    if (limit) { query += ` LIMIT $${i++}`; params.push(parseInt(limit)); }

    const result = await pool.query(query, params);
    res.json({ players: result.rows, total: result.rowCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/players/:id', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM players WHERE id = $1', [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Player not found' });
    res.json({ player: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/players', authMiddleware, adminOnly, async (req, res) => {
  const d = req.body;
  const id = genId('PLY');
  try {
    await pool.query(`
      INSERT INTO players (
        id, name, dob, class, nationality, district, division,
        school, school_contact, parent1, parent2,
        household_id, refugee_id, dad_ht, mom_ht, gender, gphp,
        scout, tier, notes, kr
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
      [id, d.name, d.dob||null, d.class||null, d.nationality||null, d.district,
       d.division||null, d.school, d.school_contact||null,
       d.parent1||null, d.parent2||null, d.household_id||null, d.refugee_id||null,
       d.dad_ht||null, d.mom_ht||null, d.gender||null, d.gphp||null,
       d.scout||null, d.tier||null, d.notes||null, d.kr||null]
    );
    const result = await pool.query('SELECT * FROM players WHERE id = $1', [id]);
    res.status(201).json({ player: result.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/players/:id', authMiddleware, adminOnly, async (req, res) => {
  const d = req.body;
  const allowed = [
    'name','dob','class','nationality','district','division','school',
    'school_contact','parent1','parent2','household_id','refugee_id',
    'dad_ht','mom_ht','gender','gphp','scout','tier','notes','kr',
    'velo','height_ft','weight_lbs','outcome','elimination_reason',
    'academy','coach_assigned','next_checkin','guardian_consent','dev_notes',
    'photo_url','batch_id','attended','age',
    'dev_velo','dev_height_ft','dev_weight_lbs','dev_broad','dev_dash','dev_kr',
    'init_velo','init_height_ft','init_notes'
  ];
  const updates = [];
  const params  = [];
  let i = 1;

  Object.entries(d).forEach(([key, val]) => {
    if (allowed.includes(key)) {
      updates.push(`${key} = $${i++}`);
      params.push(val === '' ? null : val);
    }
  });

  if (!updates.length) return res.status(400).json({ error: 'No valid fields' });
  updates.push(`updated_at = NOW()`);
  params.push(req.params.id);

  try {
    await pool.query(
      `UPDATE players SET ${updates.join(', ')} WHERE id = $${i}`, params
    );
    const result = await pool.query('SELECT * FROM players WHERE id = $1', [req.params.id]);
    res.json({ player: result.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/players/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM players WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PLAYER PHOTO UPLOAD ───────────────────────────────────────────
app.post('/api/players/:playerId/photo', authMiddleware, adminOnly,
  upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const { url } = await uploadToStorage(req.file, `players/${req.params.playerId}`);
    await pool.query('UPDATE players SET photo_url = $1 WHERE id = $2',
      [url, req.params.playerId]);
    res.json({ photo_url: url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── HOME VISIT ────────────────────────────────────────────────────
app.get('/api/players/:playerId/home-visit', authMiddleware, async (req, res) => {
  try {
    const hvR = await pool.query(
      'SELECT * FROM home_visits WHERE player_id = $1', [req.params.playerId]);
    const mediaR = await pool.query(
      'SELECT * FROM home_visit_media WHERE player_id = $1 ORDER BY created_at DESC',
      [req.params.playerId]);

    const hv = hvR.rows[0] || {};
    hv.media = mediaR.rows;
    res.json({ home_visit: hv });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/players/:playerId/home-visit', authMiddleware, adminOnly, async (req, res) => {
  const { notes, visit_date, visited_by, family_size, consent } = req.body;
  try {
    await pool.query(`
      INSERT INTO home_visits (id, player_id, notes, visit_date, visited_by, family_size, consent)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT (player_id) DO UPDATE SET
        notes = COALESCE($3, home_visits.notes),
        visit_date = COALESCE($4, home_visits.visit_date),
        visited_by = COALESCE($5, home_visits.visited_by),
        family_size = COALESCE($6, home_visits.family_size),
        consent = COALESCE($7, home_visits.consent),
        updated_at = NOW()`,
      [genId('HV'), req.params.playerId, notes||null, visit_date||null,
       visited_by||null, family_size||null, consent||false]
    );
    const r = await pool.query('SELECT * FROM home_visits WHERE player_id = $1', [req.params.playerId]);
    res.json({ home_visit: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Home visit media upload
app.post('/api/players/:playerId/home-visit/media', authMiddleware, adminOnly,
  upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const { type } = req.body;
    const { url } = await uploadToStorage(req.file, `players/${req.params.playerId}`);
    const id = genId('MED');
    await pool.query(
      `INSERT INTO home_visit_media (id, player_id, url, type, filename, filesize)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, req.params.playerId, url, type||'image',
       req.file.originalname, req.file.size]
    );
    const r = await pool.query('SELECT * FROM home_visit_media WHERE id = $1', [id]);
    res.status(201).json({ media: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/players/:playerId/home-visit/media/:mediaId', authMiddleware, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM home_visit_media WHERE id = $1', [req.params.mediaId]);
    if (r.rows[0]) {
      // Best-effort: delete the Storage object. If it was a legacy /uploads/... URL,
      // deleteFromStorage() is a no-op (the file was wiped by Railway long ago).
      try { await deleteFromStorage(r.rows[0].url); } catch (_) { /* swallow */ }
    }
    await pool.query('DELETE FROM home_visit_media WHERE id = $1', [req.params.mediaId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── TRYOUT RESULTS ────────────────────────────────────────────────
app.get('/api/tryouts/:tryoutId/results/:playerId', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM tryout_results WHERE player_id = $1', [req.params.playerId]);
    res.json({ result: r.rows[0] || null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/tryouts/:tryoutId/results/:playerId', authMiddleware, adminOnly, async (req, res) => {
  const d = req.body;
  try {
    await pool.query(`
      INSERT INTO tryout_results (
        id, player_id, batch_id,
        height_ft, weight_lbs, er,
        dash_1, dash_2, dash_avg,
        broad_1, broad_2, broad_3, broad_avg,
        velo_st_1, velo_st_2, velo_st_avg,
        velo_pd_1, velo_pd_2, velo_pd_avg,
        tier, overall_grade, scout_notes
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
      ON CONFLICT (player_id) DO UPDATE SET
        height_ft = $4, weight_lbs = $5, er = $6,
        dash_1 = $7, dash_2 = $8, dash_avg = $9,
        broad_1 = $10, broad_2 = $11, broad_3 = $12, broad_avg = $13,
        velo_st_1 = $14, velo_st_2 = $15, velo_st_avg = $16,
        velo_pd_1 = $17, velo_pd_2 = $18, velo_pd_avg = $19,
        tier = $20, overall_grade = $21, scout_notes = $22,
        updated_at = NOW()`,
      [genId('TRS'), req.params.playerId, req.params.tryoutId === 'any' ? null : req.params.tryoutId,
       d.height_ft||null, d.weight_lbs||null, d.er||null,
       d.dash_1||null, d.dash_2||null, d.dash_avg||null,
       d.broad_1||null, d.broad_2||null, d.broad_3||null, d.broad_avg||null,
       d.velo_st_1||null, d.velo_st_2||null, d.velo_st_avg||null,
       d.velo_pd_1||null, d.velo_pd_2||null, d.velo_pd_avg||null,
       d.tier||null, d.overall_grade||null, d.scout_notes||null]
    );
    // Also update player velo and height
    if (d.velo_st_avg || d.height_ft) {
      await pool.query(
        'UPDATE players SET velo = $1, height_ft = $2, weight_lbs = $3, tier = $4 WHERE id = $5',
        [d.velo_st_avg||null, d.height_ft||null, d.weight_lbs||null, d.tier||null, req.params.playerId]
      );
    }
    const r = await pool.query('SELECT * FROM tryout_results WHERE player_id = $1', [req.params.playerId]);
    res.json({ result: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── TRYOUT BATCHES ────────────────────────────────────────────────
app.get('/api/tryouts', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT tb.*,
        COUNT(DISTINCT tp.player_id) as player_count
      FROM tryout_batches tb
      LEFT JOIN tryout_players tp ON tp.batch_id = tb.id
      GROUP BY tb.id
      ORDER BY tb.tryout_date DESC NULLS LAST, tb.created_at DESC
    `);
    res.json({ tryouts: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/tryouts/:id', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM tryout_batches WHERE id = $1', [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json({ tryout: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tryouts', authMiddleware, adminOnly, async (req, res) => {
  const { name, district, tryout_date, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const id = genId('TRY');
  try {
    await pool.query(
      `INSERT INTO tryout_batches (id, name, district, tryout_date, notes)
       VALUES ($1,$2,$3,$4,$5)`,
      [id, name, district||null, tryout_date||null, notes||null]
    );
    const r = await pool.query('SELECT * FROM tryout_batches WHERE id = $1', [id]);
    res.status(201).json({ tryout: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/tryouts/:id', authMiddleware, adminOnly, async (req, res) => {
  const { name, district, tryout_date, notes, status } = req.body;
  try {
    await pool.query(
      `UPDATE tryout_batches SET name=COALESCE($1,name), district=COALESCE($2,district),
       tryout_date=COALESCE($3,tryout_date), notes=COALESCE($4,notes),
       status=COALESCE($5,status), updated_at=NOW() WHERE id=$6`,
      [name||null, district||null, tryout_date||null, notes||null, status||null, req.params.id]
    );
    const r = await pool.query('SELECT * FROM tryout_batches WHERE id = $1', [req.params.id]);
    res.json({ tryout: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Tryout players
app.get('/api/tryouts/:id/players', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT p.*,
        tp.attended, tp.added_at,
        tp.outcome        AS batch_outcome,
        tp.elimination_reason AS batch_elimination_reason,
        tp.assessed_at
      FROM tryout_players tp
      JOIN players p ON p.id = tp.player_id
      WHERE tp.batch_id = $1
      ORDER BY p.name`, [req.params.id]);
    // Use batch_outcome for display, fall back to player outcome
    const rows = r.rows.map(p => ({
      ...p,
      display_outcome: p.batch_outcome || null,
    }));
    res.json({ players: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tryouts/:id/players', authMiddleware, adminOnly, async (req, res) => {
  const { player_id } = req.body;
  try {
    await pool.query(
      'INSERT INTO tryout_players (batch_id, player_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [req.params.id, player_id]
    );
    await pool.query('UPDATE players SET batch_id = $1 WHERE id = $2', [req.params.id, player_id]);
    res.status(201).json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update batch-specific outcome for a player
app.put('/api/tryouts/:id/players/:playerId/outcome', authMiddleware, adminOnly, async (req, res) => {
  const { outcome, elimination_reason } = req.body;
  try {
    await pool.query(`
      UPDATE tryout_players
      SET outcome = $1, elimination_reason = $2, assessed_at = NOW()
      WHERE batch_id = $3 AND player_id = $4`,
      [outcome, elimination_reason || null, req.params.id, req.params.playerId]
    );
    // Also update the player's global record
    if (outcome === 'admitted') {
      await pool.query(
        "UPDATE players SET outcome = 'admitted' WHERE id = $1",
        [req.params.playerId]
      );
    } else if (outcome === 'eliminated') {
      // Only update global if player has no admitted record elsewhere
      const check = await pool.query(
        "SELECT id FROM tryout_players WHERE player_id = $1 AND outcome = 'admitted'",
        [req.params.playerId]
      );
      if (!check.rows.length) {
        await pool.query(
          "UPDATE players SET outcome = 'eliminated', elimination_reason = $1 WHERE id = $2",
          [elimination_reason || null, req.params.playerId]
        );
      }
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/tryouts/:id/players/:playerId', authMiddleware, adminOnly, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM tryout_players WHERE batch_id=$1 AND player_id=$2',
      [req.params.id, req.params.playerId]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── COMMENTS ─────────────────────────────────────────────────────
app.get('/api/players/:playerId/comments', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM comments WHERE player_id = $1 ORDER BY created_at DESC',
      [req.params.playerId]
    );
    res.json({ comments: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/players/:playerId/comments', authMiddleware, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Comment text required' });
  const id = genId('CMT');
  try {
    await pool.query(
      `INSERT INTO comments (id, player_id, author_id, author_name, text)
       VALUES ($1,$2,$3,$4,$5)`,
      [id, req.params.playerId, req.user.id, req.user.name, text]
    );
    const r = await pool.query('SELECT * FROM comments WHERE id = $1', [id]);
    res.status(201).json({ comment: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/players/:playerId/comments/:commentId', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM comments WHERE id = $1 AND author_id = $2',
      [req.params.commentId, req.user.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── SCOUTS ────────────────────────────────────────────────────────
app.get('/api/scouts', authMiddleware, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT id, username, name, role, district, active_until, login_count, last_login FROM users WHERE role = 'scout' ORDER BY name"
    );
    res.json({ scouts: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/scouts', authMiddleware, adminOnly, async (req, res) => {
  const { username, password, name, active_until, district } = req.body;
  if (!username || !password || !name)
    return res.status(400).json({ error: 'Username, password and name required' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (exists.rows[0]) return res.status(409).json({ error: 'Username already taken' });

    const hash = await bcrypt.hash(password, 10);
    const id   = genId('USR');
    await pool.query(
      `INSERT INTO users (id, username, password, name, role, active_until, district)
       VALUES ($1,$2,$3,$4,'scout',$5,$6)`,
      [id, username.toLowerCase(), hash, name, active_until||null, district||null]
    );
    const r = await pool.query(
      'SELECT id,username,name,role,district,active_until,login_count,last_login FROM users WHERE id=$1',
      [id]
    );
    res.status(201).json({ scout: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/scouts/:id', authMiddleware, adminOnly, async (req, res) => {
  const { active_until, name, district, password } = req.body;
  try {
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'UPDATE users SET active_until=$1, name=COALESCE($2,name), district=COALESCE($3,district), password=$4 WHERE id=$5',
        [active_until||null, name||null, district||null, hash, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE users SET active_until=$1, name=COALESCE($2,name), district=COALESCE($3,district) WHERE id=$4',
        [active_until||null, name||null, district||null, req.params.id]
      );
    }
    const r = await pool.query(
      'SELECT id,username,name,role,district,active_until,login_count,last_login FROM users WHERE id=$1',
      [req.params.id]
    );
    res.json({ scout: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/scouts/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── USERS (for task assignment) ───────────────────────────────────
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, username, name, role FROM users ORDER BY name'
    );
    res.json({ users: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── LOGIN ACTIVITY ────────────────────────────────────────────────
app.get('/api/activity', authMiddleware, adminOnly, async (req, res) => {
  const { limit } = req.query;
  try {
    let query = 'SELECT * FROM login_log ORDER BY created_at DESC';
    if (limit) query += ` LIMIT ${parseInt(limit)}`;
    const r = await pool.query(query);
    res.json({ logs: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── REFLECTIONS ───────────────────────────────────────────────────
app.get('/api/reflections', authMiddleware, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM reflections ORDER BY created_at DESC');
    // Parse attachments
    const rows = r.rows.map(row => ({
      ...row,
      attachments: row.attachments ? JSON.parse(row.attachments) : []
    }));
    res.json({ reflections: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reflections', authMiddleware, adminOnly,
  uploadGeneral.array('docs', 10), async (req, res) => {
  const { title, body, type } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const id = genId('REF');
  try {
    const attachments = [];
    for (const f of (req.files || [])) {
      const { url } = await uploadToStorage(f, 'reflections');
      attachments.push({
        id: uuidv4(),
        name: f.originalname,
        url,
        size: formatFileSize(f.size),
      });
    }

    await pool.query(
      `INSERT INTO reflections (id, title, body, type, author_id, author_name, attachments)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, title, body||'', type||'writeup', req.user.id, req.user.name,
       JSON.stringify(attachments)]
    );
    const r = await pool.query('SELECT * FROM reflections WHERE id = $1', [id]);
    const row = { ...r.rows[0], attachments };
    res.status(201).json({ reflection: row });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/reflections/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM reflections WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GOALS ─────────────────────────────────────────────────────────
app.get('/api/goals', authMiddleware, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM program_goals ORDER BY done ASC, created_at DESC');
    res.json({ goals: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/goals', authMiddleware, adminOnly, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Goal text required' });
  const id = genId('GOL');
  try {
    await pool.query(
      'INSERT INTO program_goals (id, text, author_id) VALUES ($1,$2,$3)',
      [id, text, req.user.id]
    );
    const r = await pool.query('SELECT * FROM program_goals WHERE id = $1', [id]);
    res.status(201).json({ goal: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/goals/:id', authMiddleware, adminOnly, async (req, res) => {
  const { done, text } = req.body;
  try {
    await pool.query(
      'UPDATE program_goals SET done=$1, text=COALESCE($2,text), updated_at=NOW() WHERE id=$3',
      [done, text||null, req.params.id]
    );
    const r = await pool.query('SELECT * FROM program_goals WHERE id = $1', [req.params.id]);
    res.json({ goal: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/goals/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM program_goals WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PDF EXPORT (basic) ────────────────────────────────────────────
app.get('/api/players/:id/pdf', authMiddleware, async (req, res) => {
  try {
    const [playerR, resultR, hvR] = await Promise.all([
      pool.query('SELECT * FROM players WHERE id = $1', [req.params.id]),
      pool.query('SELECT * FROM tryout_results WHERE player_id = $1', [req.params.id]),
      pool.query('SELECT * FROM home_visits WHERE player_id = $1', [req.params.id]),
    ]);

    const p = playerR.rows[0];
    if (!p) return res.status(404).json({ error: 'Player not found' });
    const r = resultR.rows[0] || {};
    const hv = hvR.rows[0] || {};

    // Return JSON for now — PDF generation requires puppeteer which needs more setup
    res.json({
      message: 'PDF export',
      player: p,
      tryout_result: r,
      home_visit: hv,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── HELPERS ───────────────────────────────────────────────────────
function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1024 / 1024).toFixed(1) + ' MB';
}

// routes continue below...

// ── SHAREABLE PLAYER LINKS ────────────────────────────────────────
app.post('/api/players/:id/share', authMiddleware, adminOnly, async (req, res) => {
  const { expires_hours } = req.body;
  const hours = parseInt(expires_hours) || 48;
  const token = require('crypto').randomBytes(32).toString('hex');
  const expires_at = new Date(Date.now() + hours * 60 * 60 * 1000);
  try {
    await pool.query(`
      INSERT INTO share_links (id, player_id, token, expires_at, created_by)
      VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (player_id) DO UPDATE SET
        token = $3, expires_at = $4, created_by = $5, created_at = NOW()`,
      [genId('SHL'), req.params.id, token, expires_at, req.user.id]
    );
    res.json({ token, expires_at, url: `/shared.html?token=${token}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/shared/:token', async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM share_links WHERE token = $1', [req.params.token]
    );
    const link = r.rows[0];
    if (!link) return res.status(404).json({ error: 'Link not found' });
    if (new Date(link.expires_at) < new Date())
      return res.status(410).json({ error: 'LINK_EXPIRED' });

    const [playerR, resultR, hvR, commR, mediaR] = await Promise.all([
      pool.query('SELECT * FROM players WHERE id = $1', [link.player_id]),
      pool.query('SELECT * FROM tryout_results WHERE player_id = $1', [link.player_id]),
      pool.query('SELECT * FROM home_visits WHERE player_id = $1', [link.player_id]),
      pool.query('SELECT * FROM comments WHERE player_id = $1 ORDER BY created_at DESC', [link.player_id]),
      pool.query('SELECT * FROM home_visit_media WHERE player_id = $1 ORDER BY created_at DESC', [link.player_id]),
    ]);

    const hv = hvR.rows[0] || {};
    hv.media = mediaR.rows;

    res.json({
      player:        playerR.rows[0],
      tryout_result: resultR.rows[0] || null,
      home_visit:    hv,
      comments:      commR.rows,
      expires_at:    link.expires_at,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── TWO FACTOR AUTHENTICATION ─────────────────────────────────────
// Generate 2FA secret + QR code
app.post('/api/2fa/setup', authMiddleware, adminOnly, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({
      name:   'BTID (' + req.user.username + ')',
      issuer: 'BTID Athlete Management',
      length: 20,
    });

    const qrUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Save secret temporarily (not enabled yet until verified)
    await pool.query('UPDATE users SET totp_secret = $1 WHERE id = $2',
      [secret.base32, req.user.id]);

    res.json({ secret: secret.base32, qr_code: qrUrl });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Verify and enable 2FA
app.post('/api/2fa/verify', authMiddleware, adminOnly, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code required' });
  try {
    const r = await pool.query('SELECT totp_secret FROM users WHERE id = $1', [req.user.id]);
    const secret = r.rows[0]?.totp_secret;
    if (!secret) return res.status(400).json({ error: 'Run setup first' });

    const valid = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token:    code.replace(/\s/g, ''),
      window:   1,
    });

    if (!valid) return res.status(400).json({ error: 'Invalid code. Try again.' });

    await pool.query('UPDATE users SET totp_enabled = true WHERE id = $1', [req.user.id]);
    res.json({ success: true, message: '2FA enabled successfully' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Disable 2FA
app.post('/api/2fa/disable', authMiddleware, adminOnly, async (req, res) => {
  const { code } = req.body;
  try {
    const r = await pool.query('SELECT totp_secret, totp_enabled FROM users WHERE id = $1', [req.user.id]);
    const u = r.rows[0];
    if (!u?.totp_enabled) return res.status(400).json({ error: '2FA is not enabled' });

    const valid = speakeasy.totp.verify({
      secret:   u.totp_secret,
      encoding: 'base32',
      token:    code?.replace(/\s/g, '') || '',
      window:   1,
    });
    if (!valid) return res.status(400).json({ error: 'Invalid code' });

    await pool.query('UPDATE users SET totp_enabled = false, totp_secret = NULL WHERE id = $1', [req.user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Verify 2FA code during login (second step)
app.post('/api/2fa/login-verify', async (req, res) => {
  const { temp_token, code } = req.body;
  if (!temp_token || !code) return res.status(400).json({ error: 'Token and code required' });
  try {
    // Verify the temp token
    let payload;
    try { payload = jwt.verify(temp_token, JWT_SECRET + '_2fa'); }
    catch { return res.status(401).json({ error: 'Invalid or expired session' }); }

    const r = await pool.query('SELECT * FROM users WHERE id = $1', [payload.id]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'User not found' });

    const valid = speakeasy.totp.verify({
      secret:   user.totp_secret,
      encoding: 'base32',
      token:    code.replace(/\s/g, ''),
      window:   1,
    });
    if (!valid) return res.status(401).json({ error: 'Invalid code. Please try again.' });

    // Log the login
    await pool.query(
      `INSERT INTO login_log (id, user_id, username, name, role, ip, user_agent)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [genId('LOG'), user.id, user.username, user.name, user.role,
       req.ip || req.connection.remoteAddress,
       req.headers['user-agent'] || '']
    ).catch(() => {});

    await pool.query(
      'UPDATE users SET login_count = COALESCE(login_count,0)+1, last_login = NOW() WHERE id = $1',
      [user.id]
    ).catch(() => {});

    const token = jwt.sign(
      { id: user.id, username: user.username, name: user.name, role: user.role },
      JWT_SECRET, { expiresIn: '7d' }
    );
    const { password: _, totp_secret: __, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SEASON / YEAR ROUTES ──────────────────────────────────────────
app.get('/api/seasons', authMiddleware, async (req, res) => {
  try {
    const [pr, tr] = await Promise.all([
      pool.query('SELECT DISTINCT season FROM players WHERE season IS NOT NULL ORDER BY season DESC'),
      pool.query('SELECT DISTINCT season FROM tryout_batches WHERE season IS NOT NULL ORDER BY season DESC'),
    ]);
    const seasons = [...new Set([
      ...pr.rows.map(r => r.season),
      ...tr.rows.map(r => r.season),
    ])].sort((a, b) => b - a);
    res.json({ seasons: seasons.length ? seasons : [new Date().getFullYear()] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/stats', authMiddleware, async (req, res) => {
  const { season } = req.query;
  try {
    const seasonFilter = season ? ` AND season = ${parseInt(season)}` : '';
    const [totalR, admittedR, eliminatedR, tryoutsR, tiersR] = await Promise.all([
      pool.query(`SELECT COUNT(*) FROM players WHERE 1=1${seasonFilter}`),
      pool.query(`SELECT COUNT(*) FROM players WHERE outcome = 'admitted'${seasonFilter}`),
      pool.query(`SELECT COUNT(*) FROM players WHERE outcome = 'eliminated'${seasonFilter}`),
      pool.query(`SELECT COUNT(*) FROM tryout_batches WHERE 1=1${season ? ` AND season = ${parseInt(season)}` : ''}`),
      pool.query(`SELECT tier, COUNT(*) as count FROM players WHERE tier IS NOT NULL${seasonFilter} GROUP BY tier`),
    ]);
    const tiers = {};
    tiersR.rows.forEach(r => { tiers[r.tier] = parseInt(r.count); });
    res.json({
      total:      parseInt(totalR.rows[0].count),
      admitted:   parseInt(admittedR.rows[0].count),
      eliminated: parseInt(eliminatedR.rows[0].count),
      tryouts:    parseInt(tryoutsR.rows[0].count),
      tier1:  tiers['1']   || 0,
      tier15: tiers['1.5'] || 0,
      tier2:  tiers['2']   || 0,
      tier3:  tiers['3']   || 0,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/account/2fa-status', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT totp_enabled FROM users WHERE id = $1', [req.user.id]);
    res.json({ totp_enabled: r.rows[0]?.totp_enabled || false });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PLAYER REPORTS ────────────────────────────────────────────────
app.get('/api/players/:playerId/reports', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM player_reports WHERE player_id = $1 ORDER BY created_at DESC',
      [req.params.playerId]
    );
    const rows = r.rows.map(row => ({
      ...row,
      attachments: row.attachments ? JSON.parse(row.attachments) : []
    }));
    res.json({ reports: rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/players/:playerId/reports', authMiddleware, adminOnly,
  uploadGeneral.array('files', 10), async (req, res) => {
  const { title, body } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const id = genId('RPT');
  try {
    const attachments = [];
    for (const f of (req.files || [])) {
      const { url } = await uploadToStorage(f, `players/${req.params.playerId}/reports`);
      attachments.push({
        id:   uuidv4(),
        name: f.originalname,
        url,
        size: formatFileSize(f.size),
        type: f.mimetype,
      });
    }
    await pool.query(
      `INSERT INTO player_reports (id, player_id, title, body, author_id, author_name, attachments)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, req.params.playerId, title, body||'', req.user.id, req.user.name,
       JSON.stringify(attachments)]
    );
    const r = await pool.query('SELECT * FROM player_reports WHERE id = $1', [id]);
    res.status(201).json({ report: { ...r.rows[0], attachments } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/players/:playerId/reports/:reportId', authMiddleware, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM player_reports WHERE id = $1', [req.params.reportId]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── INITIAL TRYOUT MEDIA ──────────────────────────────────────────
// ── METRICS HISTORY ──────────────────────────────────────────────
app.get('/api/players/:playerId/metrics-history', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM metrics_history WHERE player_id = $1 ORDER BY created_at DESC LIMIT 20',
      [req.params.playerId]
    );
    res.json({ history: r.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/players/:playerId/metrics-history', authMiddleware, adminOnly, async (req, res) => {
  const { velo, height_ft, weight_lbs, broad, dash, kr } = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO metrics_history (id, player_id, velo, height_ft, weight_lbs, broad, dash, kr, noted_by)
       VALUES (gen_random_uuid()::text, $1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [req.params.playerId, velo||null, height_ft||null, weight_lbs||null, broad||null, dash||null, kr||null, req.user.name||req.user.username]
    );
    res.json({ entry: r.rows[0] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/players/:playerId/initial-media', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM home_visit_media WHERE player_id = $1 AND media_tab = 'initial' ORDER BY created_at DESC",
      [req.params.playerId]
    );
    res.json({ media: r.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/players/:playerId/development-media', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM home_visit_media WHERE player_id = $1 AND media_tab = 'development' ORDER BY created_at DESC",
      [req.params.playerId]
    );
    res.json({ media: r.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/players/:playerId/media/:tab', authMiddleware, adminOnly,
  upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const tab = req.params.tab; // 'initial' | 'development' | 'homevisit' | 'final'
    const { url } = await uploadToStorage(req.file, `players/${req.params.playerId}/${tab}`);
    const id = genId('MED');
    await pool.query(
      `INSERT INTO home_visit_media (id, player_id, url, type, filename, filesize, media_tab)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, req.params.playerId, url,
       req.file.mimetype.startsWith('video') ? 'video' : 'image',
       req.file.originalname, req.file.size, tab]
    );
    const r = await pool.query('SELECT * FROM home_visit_media WHERE id = $1', [id]);
    res.status(201).json({ media: r.rows[0] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DEV NOTES LOG ────────────────────────────────────────────────
app.get('/api/players/:playerId/dev-notes', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM dev_notes_log WHERE player_id=$1 ORDER BY created_at DESC',
      [req.params.playerId]
    );
    res.json({ notes: r.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/players/:playerId/dev-notes', authMiddleware, adminOnly, async (req, res) => {
  const { note } = req.body;
  if (!note) return res.status(400).json({ error: 'Note is required' });
  try {
    const r = await pool.query(
      'INSERT INTO dev_notes_log (player_id, note, author_id, author_name) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.params.playerId, note, req.user.id, req.user.name || req.user.username]
    );
    res.status(201).json({ note: r.rows[0] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/players/:playerId/dev-notes/:noteId', authMiddleware, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM dev_notes_log WHERE id=$1 AND player_id=$2', [req.params.noteId, req.params.playerId]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── START ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`BTID API running on port ${PORT}`);
});
