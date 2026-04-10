require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'btid-secret-2025';

// ── DATABASE ──────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ── MIDDLEWARE ────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: false }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve uploaded files
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use('/uploads', express.static(uploadDir));

// ── MULTER STORAGE ────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(uploadDir, req.params.playerId || 'general');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB for videos
});

const uploadGeneral = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = path.join(uploadDir, 'reflections');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
});

// ── HELPERS ───────────────────────────────────────────────────────
function genId(prefix) {
  return prefix + '-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
}

function getFileUrl(req, filePath) {
  if (process.env.FILE_BASE_URL) return process.env.FILE_BASE_URL + '/' + filePath;
  return req.protocol + '://' + req.get('host') + '/uploads/' + filePath;
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
  res.json({ message: 'BTID Athlete Management System API', version: '1.0.0', status: 'running' });
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

    const { password: _, ...safeUser } = user;
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
  const { batch_id, district } = req.query;
  try {
    let where = 'WHERE 1=1';
    const params = [];
    let i = 1;
    if (batch_id) { where += ` AND batch_id = $${i++}`; params.push(batch_id); }
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
  const { district, tier, outcome, batch_id, limit, sort } = req.query;
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
    'photo_url','batch_id','attended','age'
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
    const photoUrl = '/uploads/' + req.params.playerId + '/' + req.file.filename;
    await pool.query('UPDATE players SET photo_url = $1 WHERE id = $2',
      [photoUrl, req.params.playerId]);
    res.json({ photo_url: photoUrl });
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
    const mediaUrl = '/uploads/' + req.params.playerId + '/' + req.file.filename;
    const id = genId('MED');
    await pool.query(
      `INSERT INTO home_visit_media (id, player_id, url, type, filename, filesize)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, req.params.playerId, mediaUrl, type||'image',
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
      const filePath = path.join(uploadDir, r.rows[0].url.replace('/uploads/', ''));
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
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
      SELECT p.*, tp.attended, tp.added_at
      FROM tryout_players tp
      JOIN players p ON p.id = tp.player_id
      WHERE tp.batch_id = $1
      ORDER BY p.name`, [req.params.id]);
    res.json({ players: r.rows });
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
    const attachments = (req.files || []).map(f => ({
      id: uuidv4(),
      name: f.originalname,
      url:  '/uploads/reflections/' + f.filename,
      size: formatFileSize(f.size),
    }));

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

// ── START ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`BTID API running on port ${PORT}`);
});
