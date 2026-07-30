const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');

require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || 'troque-esta-chave-em-producao';
const DB_PATH = path.resolve(__dirname, '..', 'data', 'auth.db');
const WEB_ROOT = path.resolve(__dirname, '..', '..');

let mailTransporter = null;

const db = new Database(DB_PATH);

db.exec(`
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

const selectUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const selectUserById = db.prepare('SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = ?');
const insertUser = db.prepare('INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?)');
const listUsersStmt = db.prepare('SELECT id, professor_name, email, city, role, created_at FROM users ORDER BY professor_name COLLATE NOCASE ASC');
const updateUserStmt = db.prepare('UPDATE users SET professor_name = ?, email = ?, city = ?, role = ? WHERE id = ?');
const updateUserWithPasswordStmt = db.prepare('UPDATE users SET professor_name = ?, email = ?, city = ?, role = ?, password_hash = ? WHERE id = ?');
const deleteUserStmt = db.prepare('DELETE FROM users WHERE id = ?');
const insertRecordStmt = db.prepare(`
  INSERT INTO records (
    nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio,
    data_termino, hora_termino, dia_termino, created_by
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const updateRecordStmt = db.prepare(`
  UPDATE records
  SET nome = ?, turma = ?, turno = ?, motivo = ?, data_entrega = ?, data_inicio = ?, hora_inicio = ?, dia_inicio = ?, data_termino = ?, hora_termino = ?, dia_termino = ?
  WHERE id = ?
`);
const listRecordsBaseSql = `
  SELECT
    id,
    nome,
    turma,
    turno,
    motivo,
    data_entrega,
    data_inicio,
    hora_inicio,
    dia_inicio,
    data_termino,
    hora_termino,
    dia_termino,
    created_at
  FROM records
`;
const deleteRecordByIdStmt = db.prepare('DELETE FROM records WHERE id = ?');
const insertPasswordResetTokenStmt = db.prepare('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)');
const invalidateUserTokensStmt = db.prepare('UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL');
const selectResetTokenStmt = db.prepare(`
  SELECT id, user_id, expires_at, used_at
  FROM password_reset_tokens
  WHERE token_hash = ?
  ORDER BY id DESC
  LIMIT 1
`);
const markTokenUsedStmt = db.prepare('UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?');
const updatePasswordByUserIdStmt = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');

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

function sanitizeRecordForResponse(record) {
  return {
    id: record.id,
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

function asBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === '') return defaultValue;
  const normalized = String(value).trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
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

function ensureSeedUser({ professorName, email, password, city, role }) {
  const normalizedEmail = normalizeEmail(email);
  const existing = selectUserByEmail.get(normalizedEmail);
  if (existing) return;
  const hash = bcrypt.hashSync(password, 10);
  insertUser.run(professorName, normalizedEmail, hash, city || '', role || 'user');
}

ensureSeedUser({
  professorName: 'Administrador',
  email: 'admin123@profe.sed.sc.gov.br',
  password: 'Senha123',
  city: 'Joinville',
  role: 'admin'
});

ensureSeedUser({
  professorName: 'Supervisao',
  email: 'supervisao@profe.sed.sc.gov.br',
  password: 'Senha123',
  city: 'Joinville',
  role: 'admin'
});

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

function isAllowedEmail(email) {
  return normalizeEmail(email).endsWith('@profe.sed.sc.gov.br');
}

function sanitizeUserForResponse(user) {
  return {
    id: user.id,
    professorName: user.professor_name,
    email: user.email,
    city: user.city,
    role: user.role,
    createdAt: user.created_at
  };
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

function canWriteRecords(req) {
  if (!req.session || !req.session.userId) return false;
  if (req.session.role === 'admin') return true;
  const user = selectUserById.get(req.session.userId);
  return !!user && normalizeEmail(user.email) === 'supervisao@profe.sed.sc.gov.br';
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, provider: 'node', now: new Date().toISOString() });
});

app.post('/api/auth/register', (req, res) => {
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
  if (selectUserByEmail.get(email)) {
    return res.status(409).json({ ok: false, message: 'Ja existe usuario com este email.' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const info = insertUser.run(professorName, email, hash, city, 'user');
  const created = selectUserById.get(info.lastInsertRowid);
  return res.status(201).json({ ok: true, user: sanitizeUserForResponse(created) });
});

app.post('/api/auth/login', (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');

  if (!email || !password) {
    return res.status(400).json({ ok: false, message: 'Informe email e senha.' });
  }

  const user = selectUserByEmail.get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ ok: false, message: 'Email ou senha invalidos.' });
  }

  req.session.userId = user.id;
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

  const user = selectUserByEmail.get(email);
  if (!user) {
    return res.json(generic);
  }

  const token = makeResetToken();
  const tokenHash = hashToken(token);
  const expiresAt = toIsoDateAfterMinutes(30);

  invalidateUserTokensStmt.run(user.id);
  insertPasswordResetTokenStmt.run(user.id, tokenHash, expiresAt);

  const payload = { ...generic };
  try {
    const delivery = await sendPasswordResetEmail(req, email, token, expiresAt);
    if (!delivery.sent) {
      payload.delivery = 'not_sent';
    } else {
      payload.delivery = 'sent';
    }
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

app.post('/api/auth/password/reset', (req, res) => {
  const token = String(req.body?.token || '').trim();
  const newPassword = String(req.body?.newPassword || '');

  if (!token || !newPassword) {
    return res.status(400).json({ ok: false, message: 'Token e nova senha sao obrigatorios.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ ok: false, message: 'A nova senha deve ter ao menos 6 caracteres.' });
  }

  const tokenHash = hashToken(token);
  const tokenRow = selectResetTokenStmt.get(tokenHash);
  if (!tokenRow || tokenRow.used_at || isTokenExpired(tokenRow.expires_at)) {
    return res.status(400).json({ ok: false, message: 'Token invalido ou expirado.' });
  }

  const hash = bcrypt.hashSync(newPassword, 10);
  updatePasswordByUserIdStmt.run(hash, tokenRow.user_id);
  markTokenUsedStmt.run(tokenRow.id);
  invalidateUserTokensStmt.run(tokenRow.user_id);

  return res.json({ ok: true, message: 'Senha redefinida com sucesso.' });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ ok: false, message: 'Sem sessao ativa.' });
  }
  const user = selectUserById.get(req.session.userId);
  if (!user) {
    return res.status(401).json({ ok: false, message: 'Usuario nao encontrado.' });
  }
  return res.json({ ok: true, user: sanitizeUserForResponse(user) });
});

app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const users = listUsersStmt.all().map(sanitizeUserForResponse);
  res.json({ ok: true, users });
});

app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
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
  if (selectUserByEmail.get(email)) {
    return res.status(409).json({ ok: false, message: 'Ja existe usuario com este email.' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const info = insertUser.run(professorName, email, hash, city, role);
  const created = selectUserById.get(info.lastInsertRowid);
  res.status(201).json({ ok: true, user: sanitizeUserForResponse(created) });
});

app.put('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
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

  const existing = selectUserById.get(id);
  if (!existing) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  const collision = selectUserByEmail.get(email);
  if (collision && Number(collision.id) !== id) {
    return res.status(409).json({ ok: false, message: 'Este email ja pertence a outro usuario.' });
  }

  if (password) {
    if (password.length < 6) {
      return res.status(400).json({ ok: false, message: 'Nova senha deve ter ao menos 6 caracteres.' });
    }
    const hash = bcrypt.hashSync(password, 10);
    updateUserWithPasswordStmt.run(professorName, email, city, role, hash, id);
  } else {
    updateUserStmt.run(professorName, email, city, role, id);
  }

  const updated = selectUserById.get(id);
  res.json({ ok: true, user: sanitizeUserForResponse(updated) });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!id) {
    return res.status(400).json({ ok: false, message: 'ID invalido.' });
  }

  const target = selectUserById.get(id);
  if (!target) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  if (target.email === 'admin123@profe.sed.sc.gov.br') {
    return res.status(400).json({ ok: false, message: 'Nao e permitido apagar o admin principal.' });
  }

  deleteUserStmt.run(id);
  res.json({ ok: true });
});

app.post('/api/records', requireAuth, (req, res) => {
  if (!canWriteRecords(req)) {
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

  const info = insertRecordStmt.run(
    nome,
    turma,
    turno,
    motivo,
    dataentrega,
    datainicio,
    horaInicio,
    diaInicio,
    datatermino,
    horaTermino,
    diaTermino,
    req.session.userId
  );

  const inserted = db.prepare('SELECT * FROM records WHERE id = ?').get(info.lastInsertRowid);
  return res.status(201).json({ ok: true, record: sanitizeRecordForResponse(inserted) });
});

function updateRecordById(req, res) {
  if (!canWriteRecords(req)) {
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

  const existing = db.prepare('SELECT id FROM records WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ ok: false, message: 'Registro nao encontrado.' });
  }

  updateRecordStmt.run(
    nome,
    turma,
    turno,
    motivo,
    dataEntrega,
    dataInicio,
    horaInicio,
    diaInicio,
    dataTermino,
    horaTermino,
    diaTermino,
    id
  );

  const updated = db.prepare('SELECT * FROM records WHERE id = ?').get(id);
  return res.json({ ok: true, record: sanitizeRecordForResponse(updated) });
}

app.put('/api/records/:id', requireAuth, updateRecordById);
app.post('/api/records/:id', requireAuth, updateRecordById);

app.get('/api/records', requireAuth, (req, res) => {
  const nome = String(req.query.nome || '').trim().toLowerCase();
  const turno = String(req.query.turno || '').trim().toLowerCase();
  const turmaCsv = String(req.query.turmas || '').trim();
  const turmaList = turmaCsv
    ? turmaCsv.split(',').map((v) => v.trim().toLowerCase()).filter(Boolean)
    : [];

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

  const sql = where.length
    ? `${listRecordsBaseSql} WHERE ${where.join(' AND ')} ORDER BY id DESC`
    : `${listRecordsBaseSql} ORDER BY id DESC`;

  const rows = db.prepare(sql).all(...params).map(sanitizeRecordForResponse);
  res.json({ ok: true, records: rows });
});

app.delete('/api/records', requireAuth, (req, res) => {
  if (!canWriteRecords(req)) {
    return res.status(403).json({ ok: false, message: 'Sem permissao para apagar atestados.' });
  }

  const idsRaw = Array.isArray(req.body?.ids) ? req.body.ids : [];
  const ids = idsRaw.map((v) => Number(v)).filter((v) => Number.isInteger(v) && v > 0);
  if (!ids.length) {
    return res.status(400).json({ ok: false, message: 'Nenhum registro selecionado para exclusao.' });
  }

  const tx = db.transaction((list) => {
    for (const id of list) {
      deleteRecordByIdStmt.run(id);
    }
  });
  tx(ids);

  res.json({ ok: true, deletedCount: ids.length });
});

app.use('/api', (req, res) => {
  res.status(404).json({ ok: false, message: 'Endpoint nao encontrado.' });
});

app.use(express.static(WEB_ROOT));

app.get('/', (req, res) => {
  res.sendFile(path.join(WEB_ROOT, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`App Node online em ./index.html (porta ${PORT})`);
});
