const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');

require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || 'troque-esta-chave-em-producao';
const DB_CONNECTION = String(process.env.DB_CONNECTION || 'sqlite').trim().toLowerCase();
const DB_PATH = path.resolve(__dirname, '..', 'data', 'auth.db');
const WEB_ROOT = path.resolve(__dirname, '..', '..');

let mailTransporter = null;
let sqliteDb = null;
let mysqlPool = null;

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function toIsoDateAfterMinutes(minutes) {
  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}

function makeResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function isTokenExpired(expiresAtIso) {
  return Date.now() > new Date(expiresAtIso).getTime();
}

function asBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === '') return defaultValue;
  const normalized = String(value).trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

function isMySql() {
  return DB_CONNECTION === 'mysql';
}

function getRecoveryPageUrl(req) {
  const configured = String(process.env.RECOVERY_PAGE_URL || '').trim();
  if (configured) return configured;
  return `${req.protocol}://${req.get('host')}/recover.html`;
}

function buildRecoveryLink(req, token) {
  const base = getRecoveryPageUrl(req);
  const separator = base.includes('?') ? '&' : '?';
  return `${base}${separator}token=${encodeURIComponent(token)}`;
}

function getSmtpTransporter() {
  if (mailTransporter) return mailTransporter;

  const host = String(process.env.SMTP_HOST || '').trim();
  const portRaw = String(process.env.SMTP_PORT || '').trim();
  const user = String(process.env.SMTP_USER || '').trim();
  const pass = String(process.env.SMTP_PASS || '').trim();

  if (!host || !portRaw || !user || !pass) {
    return null;
  }

  const port = Number(portRaw);
  if (!Number.isFinite(port) || port <= 0) {
    return null;
  }

  mailTransporter = nodemailer.createTransport({
    host,
    port,
    secure: asBoolean(process.env.SMTP_SECURE, false),
    auth: { user, pass }
  });
  return mailTransporter;
}

async function sendPasswordResetEmail(req, toEmail, token, expiresAt) {
  const transporter = getSmtpTransporter();
  if (!transporter) {
    return { sent: false, reason: 'smtp_not_configured' };
  }

  const recoveryLink = buildRecoveryLink(req, token);
  const fromEmail = String(process.env.SMTP_FROM_EMAIL || process.env.SMTP_USER || '').trim();
  const fromName = String(process.env.SMTP_FROM_NAME || 'Gestao de Atestados').trim();
  const from = fromEmail ? `${fromName} <${fromEmail}>` : fromName;

  const subject = 'Recuperacao de senha - Gestao de Atestados';
  const text = [
    'Voce solicitou a recuperacao da sua senha.',
    '',
    `Link de redefinicao: ${recoveryLink}`,
    `Token: ${token}`,
    `Expira em: ${expiresAt}`,
    '',
    'Se voce nao solicitou, ignore este e-mail.'
  ].join('\n');

  const html = [
    '<p>Voce solicitou a recuperacao da sua senha.</p>',
    `<p><strong>Link de redefinicao:</strong> <a href="${recoveryLink}">${recoveryLink}</a></p>`,
    `<p><strong>Token:</strong> ${token}</p>`,
    `<p><strong>Expira em:</strong> ${expiresAt}</p>`,
    '<p>Se voce nao solicitou, ignore este e-mail.</p>'
  ].join('');

  await transporter.sendMail({ from, to: toEmail, subject, text, html });
  return { sent: true };
}

function sanitizeUserForResponse(user) {
  return {
    id: Number(user.id),
    professorName: user.professor_name,
    email: user.email,
    city: user.city,
    role: user.role,
    createdAt: user.created_at
  };
}

function sanitizeRecordForResponse(record) {
  return {
    id: Number(record.id),
    nome: record.nome,
    turma: record.turma,
    turno: record.turno,
    motivo: record.motivo,
    dataentrega: record.data_entrega,
    datainicio: record.data_inicio,
    horaInicio: record.hora_inicio,
    diaInicio: record.dia_inicio,
    datatermino: record.data_termino,
    horaTermino: record.hora_termino,
    diaTermino: record.dia_termino,
    createdAt: record.created_at
  };
}

async function initDatabase() {
  if (isMySql()) {
    mysqlPool = mysql.createPool({
      host: String(process.env.DB_HOST || 'localhost').trim(),
      port: Number(process.env.DB_PORT || 3306),
      database: String(process.env.DB_DATABASE || '').trim(),
      user: String(process.env.DB_USERNAME || '').trim(),
      password: String(process.env.DB_PASSWORD || ''),
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });

    await mysqlPool.query(`
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

    await mysqlPool.query(`
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

    await mysqlPool.query(`
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
    return;
  }

  sqliteDb = new Database(DB_PATH);
  sqliteDb.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      professor_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      city TEXT,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      turma TEXT NOT NULL,
      turno TEXT,
      motivo TEXT,
      data_entrega TEXT,
      data_inicio TEXT,
      hora_inicio TEXT,
      dia_inicio TEXT,
      data_termino TEXT,
      hora_termino TEXT,
      dia_termino TEXT,
      created_by INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
}

async function fetchOne(sqliteSql, mysqlSql, params = []) {
  if (isMySql()) {
    const [rows] = await mysqlPool.query(mysqlSql, params);
    return rows[0] || null;
  }
  const stmt = sqliteDb.prepare(sqliteSql);
  return stmt.get(...params) || null;
}

async function fetchAll(sqliteSql, mysqlSql, params = []) {
  if (isMySql()) {
    const [rows] = await mysqlPool.query(mysqlSql, params);
    return rows;
  }
  const stmt = sqliteDb.prepare(sqliteSql);
  return stmt.all(...params);
}

async function execute(sqliteSql, mysqlSql, params = []) {
  if (isMySql()) {
    const [result] = await mysqlPool.query(mysqlSql, params);
    return result;
  }
  const stmt = sqliteDb.prepare(sqliteSql);
  return stmt.run(...params);
}

async function deleteManyRecords(ids) {
  if (isMySql()) {
    const placeholders = ids.map(() => '?').join(', ');
    await mysqlPool.query(`DELETE FROM records WHERE id IN (${placeholders})`, ids);
    return;
  }

  const tx = sqliteDb.transaction((list) => {
    const stmt = sqliteDb.prepare('DELETE FROM records WHERE id = ?');
    for (const id of list) {
      stmt.run(id);
    }
  });
  tx(ids);
}

async function ensureSeedUser({ professorName, email, password, city, role }) {
  const normalizedEmail = normalizeEmail(email);
  const existing = await fetchOne(
    'SELECT * FROM users WHERE email = ?',
    'SELECT * FROM users WHERE email = ?',
    [normalizedEmail]
  );
  if (existing) return;

  const hash = bcrypt.hashSync(password, 10);
  await execute(
    'INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)',
    'INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)',
    [professorName, normalizedEmail, hash, city || '', role || 'user']
  );
}

function isAllowedEmail(email) {
  return normalizeEmail(email).endsWith('@profe.sed.sc.gov.br');
}

async function getUserByEmail(email) {
  return fetchOne(
    'SELECT * FROM users WHERE email = ?',
    'SELECT * FROM users WHERE email = ?',
    [email]
  );
}

async function getUserById(id) {
  return fetchOne(
    'SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = ?',
    'SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = ?',
    [id]
  );
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ ok: false, message: 'Nao autenticado.' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || req.session.role !== 'admin') {
    return res.status(403).json({ ok: false, message: 'Apenas admin pode executar esta acao.' });
  }
  next();
}

async function canWriteRecords(req) {
  if (!req.session || !req.session.userId) return false;
  if (req.session.role === 'admin') return true;
  const user = await getUserById(req.session.userId);
  return !!user && normalizeEmail(user.email) === 'supervisao@profe.sed.sc.gov.br';
}

app.use(express.json());
app.use(session({
  name: 'gestao_sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60 * 8
  }
}));

app.get('/api/health', (req, res) => {
  res.json({ ok: true, provider: 'node', db: DB_CONNECTION, now: new Date().toISOString() });
});

app.post('/api/auth/register', async (req, res) => {
  const professorName = String(req.body?.professorName || '').trim();
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  const city = String(req.body?.city || '').trim();

  if (!professorName || !email || !password || !city) {
    return res.status(400).json({ ok: false, message: 'Preencha todos os campos obrigatorios.' });
  }
  if (!isAllowedEmail(email)) {
    return res.status(400).json({ ok: false, message: 'O email deve terminar com @profe.sed.sc.gov.br.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ ok: false, message: 'A senha precisa ter pelo menos 6 caracteres.' });
  }
  if (await getUserByEmail(email)) {
    return res.status(409).json({ ok: false, message: 'Ja existe usuario com este email.' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const result = await execute(
    'INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)',
    'INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)',
    [professorName, email, hash, city, 'user']
  );
  const createdId = isMySql() ? result.insertId : result.lastInsertRowid;
  const created = await getUserById(createdId);
  return res.status(201).json({ ok: true, user: sanitizeUserForResponse(created) });
});

app.post('/api/auth/login', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');

  if (!email || !password) {
    return res.status(400).json({ ok: false, message: 'Informe email e senha.' });
  }

  const user = await getUserByEmail(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ ok: false, message: 'Email ou senha invalidos.' });
  }

  req.session.userId = Number(user.id);
  req.session.role = user.role;
  return res.json({ ok: true, user: sanitizeUserForResponse(user) });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.post('/api/auth/password/forgot', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const generic = {
    ok: true,
    message: 'Se o email existir, as instrucoes de recuperacao foram geradas.'
  };

  if (!email || !isAllowedEmail(email)) {
    return res.json(generic);
  }

  const user = await getUserByEmail(email);
  if (!user) {
    return res.json(generic);
  }

  const token = makeResetToken();
  const tokenHash = hashToken(token);
  const expiresAt = toIsoDateAfterMinutes(30);

  await execute(
    'UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL',
    'UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL',
    [user.id]
  );
  await execute(
    'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
    'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
    [user.id, tokenHash, expiresAt]
  );

  const payload = { ...generic };
  try {
    const delivery = await sendPasswordResetEmail(req, email, token, expiresAt);
    payload.delivery = delivery.sent ? 'sent' : 'not_sent';
  } catch (error) {
    console.error('Erro ao enviar e-mail de recuperacao:', error);
    payload.delivery = 'failed';
  }

  if (process.env.NODE_ENV !== 'production' && asBoolean(process.env.EXPOSE_RESET_TOKEN, false)) {
    payload.resetToken = token;
    payload.resetExpiresAt = expiresAt;
  }
  return res.json(payload);
});

app.post('/api/auth/password/reset', async (req, res) => {
  const token = String(req.body?.token || '').trim();
  const newPassword = String(req.body?.newPassword || '');

  if (!token || !newPassword) {
    return res.status(400).json({ ok: false, message: 'Token e nova senha sao obrigatorios.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ ok: false, message: 'A nova senha deve ter ao menos 6 caracteres.' });
  }

  const tokenHash = hashToken(token);
  const tokenRow = await fetchOne(
    'SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = ? ORDER BY id DESC LIMIT 1',
    'SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = ? ORDER BY id DESC LIMIT 1',
    [tokenHash]
  );
  if (!tokenRow || tokenRow.used_at || isTokenExpired(tokenRow.expires_at)) {
    return res.status(400).json({ ok: false, message: 'Token invalido ou expirado.' });
  }

  const hash = bcrypt.hashSync(newPassword, 10);
  await execute('UPDATE users SET password_hash = ? WHERE id = ?', 'UPDATE users SET password_hash = ? WHERE id = ?', [hash, tokenRow.user_id]);
  await execute('UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?', 'UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?', [tokenRow.id]);
  await execute('UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL', 'UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL', [tokenRow.user_id]);

  return res.json({ ok: true, message: 'Senha redefinida com sucesso.' });
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ ok: false, message: 'Sem sessao ativa.' });
  }
  const user = await getUserById(req.session.userId);
  if (!user) {
    return res.status(401).json({ ok: false, message: 'Usuario nao encontrado.' });
  }
  return res.json({ ok: true, user: sanitizeUserForResponse(user) });
});

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await fetchAll(
    'SELECT id, professor_name, email, city, role, created_at FROM users ORDER BY professor_name COLLATE NOCASE ASC',
    'SELECT id, professor_name, email, city, role, created_at FROM users ORDER BY professor_name ASC',
    []
  );
  res.json({ ok: true, users: users.map(sanitizeUserForResponse) });
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const professorName = String(req.body?.professorName || '').trim();
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  const city = String(req.body?.city || '').trim();
  const role = req.body?.role === 'admin' ? 'admin' : 'user';

  if (!professorName || !email || !password || !city) {
    return res.status(400).json({ ok: false, message: 'Preencha todos os campos obrigatorios.' });
  }
  if (!isAllowedEmail(email)) {
    return res.status(400).json({ ok: false, message: 'O email deve terminar com @profe.sed.sc.gov.br.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ ok: false, message: 'A senha precisa ter pelo menos 6 caracteres.' });
  }
  if (await getUserByEmail(email)) {
    return res.status(409).json({ ok: false, message: 'Ja existe usuario com este email.' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const result = await execute(
    'INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)',
    'INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)',
    [professorName, email, hash, city, role]
  );
  const createdId = isMySql() ? result.insertId : result.lastInsertRowid;
  const created = await getUserById(createdId);
  res.status(201).json({ ok: true, user: sanitizeUserForResponse(created) });
});

app.put('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const professorName = String(req.body?.professorName || '').trim();
  const email = normalizeEmail(req.body?.email);
  const city = String(req.body?.city || '').trim();
  const role = req.body?.role === 'admin' ? 'admin' : 'user';
  const password = String(req.body?.password || '');

  if (!id || !professorName || !email || !city) {
    return res.status(400).json({ ok: false, message: 'Dados invalidos para atualizacao.' });
  }
  if (!isAllowedEmail(email)) {
    return res.status(400).json({ ok: false, message: 'O email deve terminar com @profe.sed.sc.gov.br.' });
  }

  const existing = await getUserById(id);
  if (!existing) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  const collision = await getUserByEmail(email);
  if (collision && Number(collision.id) !== id) {
    return res.status(409).json({ ok: false, message: 'Este email ja pertence a outro usuario.' });
  }

  if (password) {
    if (password.length < 6) {
      return res.status(400).json({ ok: false, message: 'Nova senha deve ter ao menos 6 caracteres.' });
    }
    const hash = bcrypt.hashSync(password, 10);
    await execute(
      'UPDATE users SET professor_name = ?, email = ?, city = ?, role = ?, password_hash = ? WHERE id = ?',
      'UPDATE users SET professor_name = ?, email = ?, city = ?, role = ?, password_hash = ? WHERE id = ?',
      [professorName, email, city, role, hash, id]
    );
  } else {
    await execute(
      'UPDATE users SET professor_name = ?, email = ?, city = ?, role = ? WHERE id = ?',
      'UPDATE users SET professor_name = ?, email = ?, city = ?, role = ? WHERE id = ?',
      [professorName, email, city, role, id]
    );
  }

  const updated = await getUserById(id);
  res.json({ ok: true, user: sanitizeUserForResponse(updated) });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) {
    return res.status(400).json({ ok: false, message: 'ID invalido.' });
  }

  const target = await getUserById(id);
  if (!target) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  if (target.email === 'admin123@profe.sed.sc.gov.br') {
    return res.status(400).json({ ok: false, message: 'Nao e permitido apagar o admin principal.' });
  }

  await execute('DELETE FROM users WHERE id = ?', 'DELETE FROM users WHERE id = ?', [id]);
  res.json({ ok: true });
});

app.post('/api/records', requireAuth, async (req, res) => {
  if (!(await canWriteRecords(req))) {
    return res.status(403).json({ ok: false, message: 'Sem permissao para gravar atestados.' });
  }

  const nome = String(req.body?.nome || '').trim();
  const turma = String(req.body?.turma || '').trim();
  const turno = String(req.body?.turno || '').trim();
  const motivo = String(req.body?.motivo || '').trim();
  const dataentrega = String(req.body?.dataentrega || '').trim();
  const datainicio = String(req.body?.datainicio || '').trim();
  const horaInicio = String(req.body?.horaInicio || '').trim();
  const diaInicio = String(req.body?.diaInicio || '').trim();
  const datatermino = String(req.body?.datatermino || '').trim();
  const horaTermino = String(req.body?.horaTermino || '').trim();
  const diaTermino = String(req.body?.diaTermino || '').trim();

  if (!nome || !turma || !dataentrega || !datainicio || !datatermino) {
    return res.status(400).json({ ok: false, message: 'Campos obrigatorios do atestado nao informados.' });
  }

  const result = await execute(
    `INSERT INTO records (
      nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio,
      data_termino, hora_termino, dia_termino, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    `INSERT INTO records (
      nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio,
      data_termino, hora_termino, dia_termino, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [nome, turma, turno, motivo, dataentrega, datainicio, horaInicio, diaInicio, datatermino, horaTermino, diaTermino, req.session.userId]
  );

  const insertedId = isMySql() ? result.insertId : result.lastInsertRowid;
  const inserted = await fetchOne('SELECT * FROM records WHERE id = ?', 'SELECT * FROM records WHERE id = ?', [insertedId]);
  return res.status(201).json({ ok: true, record: sanitizeRecordForResponse(inserted) });
});

async function updateRecordById(req, res) {
  if (!(await canWriteRecords(req))) {
    return res.status(403).json({ ok: false, message: 'Sem permissao para editar atestados.' });
  }

  const id = Number(req.params.id);
  const nome = String(req.body?.nome || '').trim();
  const turma = String(req.body?.turma || '').trim();
  const turno = String(req.body?.turno || '').trim();
  const motivo = String(req.body?.motivo || '').trim();
  const dataEntrega = String(req.body?.dataentrega || '').trim();
  const dataInicio = String(req.body?.datainicio || '').trim();
  const horaInicio = String(req.body?.horaInicio || '').trim();
  const diaInicio = String(req.body?.diaInicio || '').trim();
  const dataTermino = String(req.body?.datatermino || '').trim();
  const horaTermino = String(req.body?.horaTermino || '').trim();
  const diaTermino = String(req.body?.diaTermino || '').trim();

  if (!id || !nome || !turma || !dataEntrega || !dataInicio || !dataTermino) {
    return res.status(400).json({ ok: false, message: 'Campos obrigatorios do atestado nao informados.' });
  }

  const existing = await fetchOne('SELECT id FROM records WHERE id = ?', 'SELECT id FROM records WHERE id = ?', [id]);
  if (!existing) {
    return res.status(404).json({ ok: false, message: 'Registro nao encontrado.' });
  }

  await execute(
    'UPDATE records SET nome = ?, turma = ?, turno = ?, motivo = ?, data_entrega = ?, data_inicio = ?, hora_inicio = ?, dia_inicio = ?, data_termino = ?, hora_termino = ?, dia_termino = ? WHERE id = ?',
    'UPDATE records SET nome = ?, turma = ?, turno = ?, motivo = ?, data_entrega = ?, data_inicio = ?, hora_inicio = ?, dia_inicio = ?, data_termino = ?, hora_termino = ?, dia_termino = ? WHERE id = ?',
    [nome, turma, turno, motivo, dataEntrega, dataInicio, horaInicio, diaInicio, dataTermino, horaTermino, diaTermino, id]
  );

  const updated = await fetchOne('SELECT * FROM records WHERE id = ?', 'SELECT * FROM records WHERE id = ?', [id]);
  return res.json({ ok: true, record: sanitizeRecordForResponse(updated) });
}

app.put('/api/records/:id', requireAuth, updateRecordById);
app.post('/api/records/:id', requireAuth, updateRecordById);

app.get('/api/records', requireAuth, async (req, res) => {
  const nome = String(req.query.nome || '').trim().toLowerCase();
  const turno = String(req.query.turno || '').trim().toLowerCase();
  const turmaCsv = String(req.query.turmas || '').trim();
  const turmaList = turmaCsv ? turmaCsv.split(',').map((v) => v.trim().toLowerCase()).filter(Boolean) : [];

  const where = [];
  const params = [];

  if (nome) {
    where.push('LOWER(nome) LIKE ?');
    params.push(`%${nome}%`);
  }
  if (turno) {
    where.push('LOWER(turno) LIKE ?');
    params.push(`%${turno}%`);
  }
  if (turmaList.length) {
    const turmaClauses = turmaList.map(() => 'LOWER(turma) LIKE ?').join(' OR ');
    where.push(`(${turmaClauses})`);
    turmaList.forEach((turmaTerm) => params.push(`%${turmaTerm}%`));
  }

  const baseSql = 'SELECT id, nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio, data_termino, hora_termino, dia_termino, created_at FROM records';
  const sql = where.length ? `${baseSql} WHERE ${where.join(' AND ')} ORDER BY id DESC` : `${baseSql} ORDER BY id DESC`;
  const rows = await fetchAll(sql, sql, params);
  res.json({ ok: true, records: rows.map(sanitizeRecordForResponse) });
});

app.delete('/api/records', requireAuth, async (req, res) => {
  if (!(await canWriteRecords(req))) {
    return res.status(403).json({ ok: false, message: 'Sem permissao para apagar atestados.' });
  }

  const idsRaw = Array.isArray(req.body?.ids) ? req.body.ids : [];
  const ids = idsRaw.map((v) => Number(v)).filter((v) => Number.isInteger(v) && v > 0);
  if (!ids.length) {
    return res.status(400).json({ ok: false, message: 'Nenhum registro selecionado para exclusao.' });
  }

  await deleteManyRecords(ids);
  res.json({ ok: true, deletedCount: ids.length });
});

app.use('/api', (req, res) => {
  res.status(404).json({ ok: false, message: 'Endpoint nao encontrado.' });
});

app.use(express.static(WEB_ROOT));

app.get('/', (req, res) => {
  res.sendFile(path.join(WEB_ROOT, 'index.html'));
});

async function start() {
  await initDatabase();

  await ensureSeedUser({
    professorName: 'Administrador',
    email: 'admin123@profe.sed.sc.gov.br',
    password: 'Senha123',
    city: 'Joinville',
    role: 'admin'
  });

  await ensureSeedUser({
    professorName: 'Supervisao',
    email: 'supervisao@profe.sed.sc.gov.br',
    password: 'Senha123',
    city: 'Joinville',
    role: 'admin'
  });

  app.listen(PORT, () => {
    console.log(`App Node online em ./index.html (porta ${PORT}) usando ${DB_CONNECTION}`);
  });
}

start().catch((error) => {
  console.error('Falha ao iniciar backend Node:', error);
  process.exit(1);
});
