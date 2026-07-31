const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');

const AUTH_COOKIE = 'gestao_auth';
const AUTH_TTL_MS = 1000 * 60 * 60 * 8;
const SEED_PASSWORD = 'Senha123';
const ALLOWED_EMAIL_DOMAIN = '@profe.sed.sc.gov.br';
const CORS_ORIGIN_WHITELIST = new Set([
  'https://projeto-gest-o-atestados-zim2.vercel.app',
  'http://localhost:3000',
  'http://localhost:8000',
  'null'
]);

let poolPromise = null;
let seedPasswordHash = null;

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isAllowedEmail(email) {
  return normalizeEmail(email).endsWith(ALLOWED_EMAIL_DOMAIN);
}

function getDbConfig() {
  const dbName = String(process.env.DB_DATABASE || '').trim();
  const dbUser = String(process.env.DB_USERNAME || '').trim();
  const dbPass = String(process.env.DB_PASSWORD || '');

  if (!dbName || !dbUser) {
    throw new Error('Configuracao do banco ausente. Defina DB_DATABASE e DB_USERNAME.');
  }

  return {
    host: String(process.env.DB_HOST || 'localhost').trim(),
    port: Number(process.env.DB_PORT || 3306),
    database: dbName,
    user: dbUser,
    password: dbPass,
    waitForConnections: true,
    connectionLimit: 4,
    queueLimit: 0,
    timezone: 'Z'
  };
}

async function getPool() {
  if (!poolPromise) {
    poolPromise = mysql.createPool(getDbConfig());
  }
  return poolPromise;
}

function getSeedPasswordHash() {
  if (!seedPasswordHash) {
    seedPasswordHash = bcrypt.hashSync(SEED_PASSWORD, 10);
  }
  return seedPasswordHash;
}

async function initSchema() {
  const pool = await getPool();

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT NOT NULL AUTO_INCREMENT,
      professor_name VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      city VARCHAR(120) DEFAULT NULL,
      role VARCHAR(50) NOT NULL DEFAULT 'user',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uk_users_email (email),
      KEY idx_users_email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS records (
      id INT NOT NULL AUTO_INCREMENT,
      nome VARCHAR(255) NOT NULL,
      turma VARCHAR(100) NOT NULL,
      turno VARCHAR(100) DEFAULT NULL,
      motivo VARCHAR(150) DEFAULT NULL,
      data_entrega VARCHAR(20) DEFAULT NULL,
      data_inicio VARCHAR(20) DEFAULT NULL,
      hora_inicio VARCHAR(20) DEFAULT NULL,
      dia_inicio VARCHAR(50) DEFAULT NULL,
      data_termino VARCHAR(20) DEFAULT NULL,
      hora_termino VARCHAR(20) DEFAULT NULL,
      dia_termino VARCHAR(50) DEFAULT NULL,
      created_by INT DEFAULT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_records_nome (nome),
      KEY idx_records_turma (turma),
      KEY idx_records_turno (turno),
      KEY idx_records_created_by (created_by),
      CONSTRAINT fk_records_created_by FOREIGN KEY (created_by) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id INT NOT NULL AUTO_INCREMENT,
      user_id INT NOT NULL,
      token_hash VARCHAR(255) NOT NULL,
      expires_at VARCHAR(64) NOT NULL,
      used_at DATETIME DEFAULT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_reset_tokens_user_id (user_id),
      KEY idx_reset_tokens_token_hash (token_hash),
      CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  const seeds = [
    ['Administrador', 'admin123@profe.sed.sc.gov.br', 'admin', 'Joinville'],
    ['Supervisao', 'supervisao@profe.sed.sc.gov.br', 'admin', 'Joinville'],
    ['Priscila', 'priscila@profe.sed.sc.gov.br', 'user', 'Joinville'],
    ['Cesar', 'cesar@profe.sed.sc.gov.br', 'user', 'Joinville']
  ];

  for (const [professorName, email, role, city] of seeds) {
    await pool.query(
      'INSERT IGNORE INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)',
      [professorName, normalizeEmail(email), getSeedPasswordHash(), city, role]
    );
  }
}

function parseJsonBody(req) {
  if (req.body && typeof req.body === 'object') {
    return req.body;
  }

  if (typeof req.body === 'string' && req.body.trim()) {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }

  return {};
}

function parseCookies(req) {
  const header = String(req.headers.cookie || '');
  const cookies = {};

  header.split(';').forEach((part) => {
    const index = part.indexOf('=');
    if (index === -1) return;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) cookies[name] = decodeURIComponent(value);
  });

  return cookies;
}

function getRequestOrigin(req) {
  const origin = String(req.headers.origin || req.headers.Origin || '').trim();
  if (origin) return origin;

  const referer = String(req.headers.referer || req.headers.Referrer || '').trim();
  if (!referer) return '';

  try {
    return new URL(referer).origin;
  } catch {
    return '';
  }
}

function getCorsHeaders(req) {
  const origin = getRequestOrigin(req);
  if (!origin || !CORS_ORIGIN_WHITELIST.has(origin)) {
    return {};
  }

  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
  };
}

function authSecret() {
  return String(process.env.AUTH_SECRET || process.env.SESSION_SECRET || 'troque-esta-chave-em-producao');
}

function signAuthPayload(payload) {
  const raw = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', authSecret()).update(raw).digest('base64url');
  return `${raw}.${sig}`;
}

function verifyAuthToken(token) {
  if (!token || typeof token !== 'string') return null;
  const [raw, sig] = token.split('.');
  if (!raw || !sig) return null;

  const expected = crypto.createHmac('sha256', authSecret()).update(raw).digest('base64url');
  const sigBuffer = Buffer.from(sig);
  const expectedBuffer = Buffer.from(expected);
  if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
    if (!payload || typeof payload !== 'object') return null;
    if (payload.exp && Date.now() > Number(payload.exp)) return null;
    return payload;
  } catch {
    return null;
  }
}

function cookieOptions(req) {
  const origin = getRequestOrigin(req);
  const isCrossOrigin = !!origin && origin !== 'https://projeto-gest-o-atestados-zim2.vercel.app';
  const parts = [
    `${AUTH_COOKIE}=%s`,
    'HttpOnly',
    'Path=/',
    `Max-Age=${Math.floor(AUTH_TTL_MS / 1000)}`
  ];

  if (isCrossOrigin) {
    parts.push('SameSite=None');
    parts.push('Secure');
  } else {
    parts.push('SameSite=Lax');
    if (String(process.env.NODE_ENV || '').toLowerCase() === 'production') {
      parts.push('Secure');
    }
  }

  return parts.join('; ');
}

function setAuthCookie(req, res, token) {
  res.setHeader('Set-Cookie', cookieOptions(req).replace('%s', encodeURIComponent(token)));
}

function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', `${AUTH_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
}

function send(res, statusCode, payload, headers = {}) {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  Object.entries(headers).forEach(([key, value]) => res.setHeader(key, value));
  res.end(JSON.stringify(payload));
}

function sanitizeUser(row) {
  return {
    id: Number(row.id),
    professorName: row.professor_name,
    email: row.email,
    city: row.city ?? '',
    role: row.role,
    createdAt: row.created_at
  };
}

function sanitizeRecord(row) {
  return {
    id: Number(row.id),
    nome: row.nome,
    turma: row.turma,
    turno: row.turno,
    motivo: row.motivo,
    dataentrega: row.data_entrega,
    datainicio: row.data_inicio,
    horaInicio: row.hora_inicio,
    diaInicio: row.dia_inicio,
    datatermino: row.data_termino,
    horaTermino: row.hora_termino,
    diaTermino: row.dia_termino,
    createdAt: row.created_at
  };
}

async function getCurrentUser(req) {
  const cookies = parseCookies(req);
  const token = cookies[AUTH_COOKIE];
  const payload = verifyAuthToken(token);
  if (!payload || !payload.userId) return null;

  const pool = await getPool();
  const [rows] = await pool.query(
    'SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = ? LIMIT 1',
    [Number(payload.userId)]
  );
  return rows[0] || null;
}

function canWriteRecords(user) {
  if (!user) return false;
  const email = normalizeEmail(user.email);
  return user.role === 'admin' || email === 'supervisao@profe.sed.sc.gov.br';
}

function nowPlusMinutesIso(minutes) {
  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function makeResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function initAndGetPool() {
  await initSchema();
  return getPool();
}

function getPathSegments(req) {
  const raw = Array.isArray(req.query?.path) ? req.query.path : [];
  if (raw.length) return raw.map((segment) => String(segment || '').trim()).filter(Boolean);

  const pathname = String(req.url || '')
    .replace(/^\/api\/?/, '')
    .split('?')[0]
    .split('/')
    .filter(Boolean);
  return pathname;
}

async function handleHealth(req, res) {
  const db = String(process.env.DB_DATABASE || '').trim();
  send(res, 200, { ok: true, provider: 'vercel-node', db, now: new Date().toISOString() }, getCorsHeaders(req));
}

async function handleLogin(req, res) {
  const pool = await initAndGetPool();
  const body = parseJsonBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');

  if (!email || !password) {
    return send(res, 400, { ok: false, message: 'Informe email e senha.' });
  }

  const [rows] = await pool.query('SELECT * FROM users WHERE email = ? LIMIT 1', [email]);
  const user = rows[0];
  if (!user || !bcrypt.compareSync(password, String(user.password_hash || ''))) {
    return send(res, 401, { ok: false, message: 'Email ou senha invalidos.' });
  }

  const token = signAuthPayload({ userId: Number(user.id), exp: Date.now() + AUTH_TTL_MS });
  setAuthCookie(req, res, token);
  return send(res, 200, { ok: true, user: sanitizeUser(user) }, getCorsHeaders(req));
}

async function handleLogout(req, res) {
  clearAuthCookie(res);
  return send(res, 200, { ok: true }, getCorsHeaders(req));
}

async function handleMe(req, res) {
  const user = await getCurrentUser(req);
  if (!user) {
    return send(res, 401, { ok: false, message: 'Nao autenticado.' }, getCorsHeaders(req));
  }
  return send(res, 200, { ok: true, user: sanitizeUser(user) }, getCorsHeaders(req));
}

async function handleRegister(req, res) {
  const pool = await initAndGetPool();
  const body = parseJsonBody(req);
  const professorName = String(body.professorName || '').trim();
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  const city = String(body.city || '').trim();

  if (!professorName || !email || !password || !city) {
    return send(res, 400, { ok: false, message: 'Preencha todos os campos obrigatorios.' }, getCorsHeaders(req));
  }
  if (!isAllowedEmail(email)) {
    return send(res, 400, { ok: false, message: 'O email deve terminar com @profe.sed.sc.gov.br.' }, getCorsHeaders(req));
  }
  if (password.length < 6) {
    return send(res, 400, { ok: false, message: 'A senha precisa ter pelo menos 6 caracteres.' }, getCorsHeaders(req));
  }

  const [existing] = await pool.query('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
  if (existing.length) {
    return send(res, 409, { ok: false, message: 'Ja existe usuario com este email.' }, getCorsHeaders(req));
  }

  const [result] = await pool.query(
    'INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)',
    [professorName, email, bcrypt.hashSync(password, 10), city, 'user']
  );

  const [createdRows] = await pool.query(
    'SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = ? LIMIT 1',
    [result.insertId]
  );
  return send(res, 201, { ok: true, user: sanitizeUser(createdRows[0]) }, getCorsHeaders(req));
}

async function handlePasswordForgot(req, res) {
  const pool = await initAndGetPool();
  const body = parseJsonBody(req);
  const email = normalizeEmail(body.email);
  const generic = { ok: true, message: 'Se o email existir, as instrucoes de recuperacao foram geradas.' };

  if (!email || !isAllowedEmail(email)) {
    return send(res, 200, generic, getCorsHeaders(req));
  }

  const [rows] = await pool.query('SELECT * FROM users WHERE email = ? LIMIT 1', [email]);
  const user = rows[0];
  if (!user) {
    return send(res, 200, generic, getCorsHeaders(req));
  }

  const token = makeResetToken();
  const tokenHash = hashToken(token);
  const expiresAt = nowPlusMinutesIso(30);

  await pool.query('UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL', [user.id]);
  await pool.query('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)', [user.id, tokenHash, expiresAt]);

  const payload = { ...generic, delivery: 'not_configured' };
  if (String(process.env.NODE_ENV || '').toLowerCase() !== 'production' || String(process.env.EXPOSE_RESET_TOKEN || '') === '1') {
    payload.resetToken = token;
    payload.resetExpiresAt = expiresAt;
  }
  return send(res, 200, payload, getCorsHeaders(req));
}

async function handlePasswordReset(req, res) {
  const pool = await initAndGetPool();
  const body = parseJsonBody(req);
  const token = String(body.token || '').trim();
  const newPassword = String(body.newPassword || '');

  if (!token || !newPassword) {
    return send(res, 400, { ok: false, message: 'Token e nova senha sao obrigatorios.' }, getCorsHeaders(req));
  }
  if (newPassword.length < 6) {
    return send(res, 400, { ok: false, message: 'A nova senha deve ter ao menos 6 caracteres.' }, getCorsHeaders(req));
  }

  const tokenHash = hashToken(token);
  const [rows] = await pool.query(
    'SELECT * FROM password_reset_tokens WHERE token_hash = ? ORDER BY id DESC LIMIT 1',
    [tokenHash]
  );
  const resetRow = rows[0];
  if (!resetRow || resetRow.used_at || new Date(resetRow.expires_at).getTime() < Date.now()) {
    return send(res, 400, { ok: false, message: 'Token invalido ou expirado.' }, getCorsHeaders(req));
  }

  await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [bcrypt.hashSync(newPassword, 10), resetRow.user_id]);
  await pool.query('UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?', [resetRow.id]);
  return send(res, 200, { ok: true, message: 'Senha redefinida com sucesso.' }, getCorsHeaders(req));
}

async function handleUsersList(req, res) {
  const user = await getCurrentUser(req);
  if (!user) return send(res, 401, { ok: false, message: 'Nao autenticado.' }, getCorsHeaders(req));
  if (user.role !== 'admin') return send(res, 403, { ok: false, message: 'Apenas admin pode executar esta acao.' }, getCorsHeaders(req));

  const pool = await initAndGetPool();
  const [rows] = await pool.query(
    'SELECT id, professor_name, email, city, role, created_at FROM users ORDER BY professor_name ASC'
  );
  return send(res, 200, { ok: true, users: rows.map(sanitizeUser) }, getCorsHeaders(req));
}

async function handleUsersCreate(req, res) {
  const user = await getCurrentUser(req);
  if (!user) return send(res, 401, { ok: false, message: 'Nao autenticado.' }, getCorsHeaders(req));
  if (user.role !== 'admin') return send(res, 403, { ok: false, message: 'Apenas admin pode executar esta acao.' }, getCorsHeaders(req));

  const pool = await initAndGetPool();
  const body = parseJsonBody(req);
  const professorName = String(body.professorName || '').trim();
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  const city = String(body.city || '').trim();
  const role = String(body.role || 'user') === 'admin' ? 'admin' : 'user';

  if (!professorName || !email || !password || !city) {
    return send(res, 400, { ok: false, message: 'Preencha todos os campos obrigatorios.' }, getCorsHeaders(req));
  }
  if (!isAllowedEmail(email)) {
    return send(res, 400, { ok: false, message: 'O email deve terminar com @profe.sed.sc.gov.br.' }, getCorsHeaders(req));
  }

  const [existing] = await pool.query('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
  if (existing.length) {
    return send(res, 409, { ok: false, message: 'Ja existe usuario com este email.' }, getCorsHeaders(req));
  }

  const [result] = await pool.query(
    'INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)',
    [professorName, email, bcrypt.hashSync(password, 10), city, role]
  );
  const [createdRows] = await pool.query('SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = ? LIMIT 1', [result.insertId]);
  return send(res, 201, { ok: true, user: sanitizeUser(createdRows[0]) }, getCorsHeaders(req));
}

async function handleUsersUpdate(req, res, id) {
  const user = await getCurrentUser(req);
  if (!user) return send(res, 401, { ok: false, message: 'Nao autenticado.' }, getCorsHeaders(req));
  if (user.role !== 'admin') return send(res, 403, { ok: false, message: 'Apenas admin pode executar esta acao.' }, getCorsHeaders(req));

  const pool = await initAndGetPool();
  const body = parseJsonBody(req);
  const professorName = String(body.professorName || '').trim();
  const email = normalizeEmail(body.email);
  const city = String(body.city || '').trim();
  const role = String(body.role || 'user') === 'admin' ? 'admin' : 'user';
  const password = String(body.password || '');

  if (!professorName || !email || !city) {
    return send(res, 400, { ok: false, message: 'Preencha todos os campos obrigatorios.' }, getCorsHeaders(req));
  }

  const [collision] = await pool.query('SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1', [email, id]);
  if (collision.length) {
    return send(res, 409, { ok: false, message: 'Ja existe usuario com este email.' }, getCorsHeaders(req));
  }

  if (password) {
    await pool.query(
      'UPDATE users SET professor_name = ?, email = ?, city = ?, role = ?, password_hash = ? WHERE id = ?',
      [professorName, email, city, role, bcrypt.hashSync(password, 10), id]
    );
  } else {
    await pool.query(
      'UPDATE users SET professor_name = ?, email = ?, city = ?, role = ? WHERE id = ?',
      [professorName, email, city, role, id]
    );
  }

  const [updatedRows] = await pool.query('SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = ? LIMIT 1', [id]);
  if (!updatedRows.length) {
    return send(res, 404, { ok: false, message: 'Usuario nao encontrado.' }, getCorsHeaders(req));
  }
  return send(res, 200, { ok: true, user: sanitizeUser(updatedRows[0]) }, getCorsHeaders(req));
}

async function handleUsersDelete(req, res, id) {
  const user = await getCurrentUser(req);
  if (!user) return send(res, 401, { ok: false, message: 'Nao autenticado.' }, getCorsHeaders(req));
  if (user.role !== 'admin') return send(res, 403, { ok: false, message: 'Apenas admin pode executar esta acao.' }, getCorsHeaders(req));

  const pool = await initAndGetPool();
  if (normalizeEmail(user.email) === 'admin123@profe.sed.sc.gov.br' && Number(user.id) === Number(id)) {
    return send(res, 400, { ok: false, message: 'Nao e permitido apagar o usuario administrador principal.' }, getCorsHeaders(req));
  }

  await pool.query('DELETE FROM users WHERE id = ?', [id]);
  return send(res, 200, { ok: true, deleted: true }, getCorsHeaders(req));
}

async function handleRecordsList(req, res) {
  const user = await getCurrentUser(req);
  if (!user) return send(res, 401, { ok: false, message: 'Nao autenticado.' }, getCorsHeaders(req));

  const pool = await initAndGetPool();
  const filters = [];
  const params = [];
  const q = req.query || {};

  if (String(q.nome || '').trim()) {
    filters.push('LOWER(nome) LIKE ?');
    params.push(`%${String(q.nome).trim().toLowerCase()}%`);
  }
  if (String(q.turno || '').trim()) {
    filters.push('LOWER(turno) LIKE ?');
    params.push(`%${String(q.turno).trim().toLowerCase()}%`);
  }
  if (String(q.turmas || '').trim()) {
    const terms = String(q.turmas).split(',').map((part) => part.trim().toLowerCase()).filter(Boolean);
    if (terms.length) {
      filters.push(`(${terms.map(() => 'LOWER(turma) LIKE ?').join(' OR ')})`);
      terms.forEach((term) => params.push(`%${term}%`));
    }
  }

  const where = filters.length ? ` WHERE ${filters.join(' AND ')}` : '';
  const [rows] = await pool.query(
    `SELECT id, nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio, data_termino, hora_termino, dia_termino, created_at FROM records${where} ORDER BY id DESC`,
    params
  );
  return send(res, 200, { ok: true, records: rows.map(sanitizeRecord) }, getCorsHeaders(req));
}

async function handleRecordCreate(req, res) {
  const user = await getCurrentUser(req);
  if (!user) return send(res, 401, { ok: false, message: 'Nao autenticado.' }, getCorsHeaders(req));

  const body = parseJsonBody(req);
  const pool = await initAndGetPool();

  const values = {
    nome: String(body.nome || '').trim(),
    turma: String(body.turma || '').trim(),
    turno: String(body.turno || '').trim(),
    motivo: String(body.motivo || '').trim(),
    data_entrega: String(body.dataentrega || '').trim(),
    data_inicio: String(body.datainicio || '').trim(),
    hora_inicio: String(body.horaInicio || '').trim(),
    dia_inicio: String(body.diaInicio || '').trim(),
    data_termino: String(body.datatermino || '').trim(),
    hora_termino: String(body.horaTermino || '').trim(),
    dia_termino: String(body.diaTermino || '').trim()
  };

  if (!values.nome || !values.turma) {
    return send(res, 400, { ok: false, message: 'Preencha nome e turma.' }, getCorsHeaders(req));
  }

  if (!canWriteRecords(user)) {
    return send(res, 403, { ok: false, message: 'Sem permissao para gravar atestados.' }, getCorsHeaders(req));
  }

  const [result] = await pool.query(
    `INSERT INTO records (nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio, data_termino, hora_termino, dia_termino, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [values.nome, values.turma, values.turno, values.motivo, values.data_entrega, values.data_inicio, values.hora_inicio, values.dia_inicio, values.data_termino, values.hora_termino, values.dia_termino, user.id]
  );

  const [createdRows] = await pool.query(
    'SELECT id, nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio, data_termino, hora_termino, dia_termino, created_at FROM records WHERE id = ? LIMIT 1',
    [result.insertId]
  );
  return send(res, 201, { ok: true, record: sanitizeRecord(createdRows[0]) }, getCorsHeaders(req));
}

async function handleRecordUpdate(req, res, id) {
  const user = await getCurrentUser(req);
  if (!user) return send(res, 401, { ok: false, message: 'Nao autenticado.' }, getCorsHeaders(req));

  const body = parseJsonBody(req);
  const pool = await initAndGetPool();

  const values = {
    nome: String(body.nome || '').trim(),
    turma: String(body.turma || '').trim(),
    turno: String(body.turno || '').trim(),
    motivo: String(body.motivo || '').trim(),
    data_entrega: String(body.dataentrega || '').trim(),
    data_inicio: String(body.datainicio || '').trim(),
    hora_inicio: String(body.horaInicio || '').trim(),
    dia_inicio: String(body.diaInicio || '').trim(),
    data_termino: String(body.datatermino || '').trim(),
    hora_termino: String(body.horaTermino || '').trim(),
    dia_termino: String(body.diaTermino || '').trim()
  };

  if (!values.nome || !values.turma) {
    return send(res, 400, { ok: false, message: 'Preencha nome e turma.' }, getCorsHeaders(req));
  }

  const [existing] = await pool.query('SELECT id FROM records WHERE id = ? LIMIT 1', [id]);
  if (!existing.length) {
    return send(res, 404, { ok: false, message: 'Registro nao encontrado.' }, getCorsHeaders(req));
  }

  await pool.query(
    `UPDATE records SET nome = ?, turma = ?, turno = ?, motivo = ?, data_entrega = ?, data_inicio = ?, hora_inicio = ?, dia_inicio = ?, data_termino = ?, hora_termino = ?, dia_termino = ? WHERE id = ?`,
    [values.nome, values.turma, values.turno, values.motivo, values.data_entrega, values.data_inicio, values.hora_inicio, values.dia_inicio, values.data_termino, values.hora_termino, values.dia_termino, id]
  );

  const [updatedRows] = await pool.query(
    'SELECT id, nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio, data_termino, hora_termino, dia_termino, created_at FROM records WHERE id = ? LIMIT 1',
    [id]
  );
  return send(res, 200, { ok: true, record: sanitizeRecord(updatedRows[0]) }, getCorsHeaders(req));
}

async function handleRecordsDelete(req, res) {
  const user = await getCurrentUser(req);
  if (!user) return send(res, 401, { ok: false, message: 'Nao autenticado.' }, getCorsHeaders(req));
  if (!canWriteRecords(user)) return send(res, 403, { ok: false, message: 'Sem permissao para apagar atestados.' }, getCorsHeaders(req));

  const pool = await initAndGetPool();
  const body = parseJsonBody(req);
  const ids = Array.isArray(body.ids) ? body.ids.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value > 0) : [];

  if (!ids.length) {
    return send(res, 400, { ok: false, message: 'Nenhum registro selecionado para exclusao.' }, getCorsHeaders(req));
  }

  await pool.query(`DELETE FROM records WHERE id IN (${ids.map(() => '?').join(', ')})`, ids);
  return send(res, 200, { ok: true, deletedCount: ids.length }, getCorsHeaders(req));
}

async function handler(req, res) {
  try {
    const segments = getPathSegments(req);
    const [first, second] = segments;
    const method = String(req.method || 'GET').toUpperCase();

    if (method === 'OPTIONS') {
      return send(res, 204, {}, getCorsHeaders(req));
    }

    if (method === 'GET' && (!first || first === 'health')) return handleHealth(req, res);
    if (first === 'auth' && second === 'login' && method === 'POST') return handleLogin(req, res);
    if (first === 'auth' && second === 'logout' && method === 'POST') return handleLogout(req, res);
    if (first === 'auth' && second === 'me' && method === 'GET') return handleMe(req, res);
    if (first === 'auth' && second === 'register' && method === 'POST') return handleRegister(req, res);
    if (first === 'auth' && second === 'password' && segments[2] === 'forgot' && method === 'POST') return handlePasswordForgot(req, res);
    if (first === 'auth' && second === 'password' && segments[2] === 'reset' && method === 'POST') return handlePasswordReset(req, res);

    if (first === 'users' && method === 'GET') return handleUsersList(req, res);
    if (first === 'users' && method === 'POST') return handleUsersCreate(req, res);
    if (first === 'users' && segments[1] && method === 'PUT') return handleUsersUpdate(req, res, Number(segments[1]));
    if (first === 'users' && segments[1] && method === 'DELETE') return handleUsersDelete(req, res, Number(segments[1]));

    if (first === 'records' && method === 'GET') return handleRecordsList(req, res);
    if (first === 'records' && method === 'POST' && segments.length === 1) return handleRecordCreate(req, res);
    if (first === 'records' && segments[1] && (method === 'PUT' || method === 'POST')) return handleRecordUpdate(req, res, Number(segments[1]));
    if (first === 'records' && method === 'DELETE') return handleRecordsDelete(req, res);

    return send(res, 404, { ok: false, message: 'Endpoint nao encontrado.' }, getCorsHeaders(req));
  } catch (error) {
    return send(res, 500, { ok: false, message: error.message || 'Falha interna no servidor.' }, getCorsHeaders(req));
  }
}

module.exports = handler;