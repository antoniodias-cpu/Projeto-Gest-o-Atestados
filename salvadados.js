const mysql = require('mysql2/promise');

let poolPromise = null;

function parseDatabaseUrl(rawUrl) {
  const value = String(rawUrl || '').trim();
  if (!value) return null;

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('DATABASE_URL invalida. Use mysql://usuario:senha@host:3306/banco');
  }

  if (!/^mysql:?$/i.test(parsed.protocol)) {
    throw new Error('DATABASE_URL deve usar protocolo mysql://');
  }

  const database = parsed.pathname.replace(/^\//, '').trim();
  if (!database || !parsed.username) {
    throw new Error('DATABASE_URL incompleta. Informe usuario e banco.');
  }

  return {
    host: parsed.hostname,
    port: Number(parsed.port || 3306),
    database,
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password || ''),
    waitForConnections: true,
    connectionLimit: 4,
    queueLimit: 0,
    timezone: 'Z'
  };
}

function getDbConfig() {
  const fromUrl = parseDatabaseUrl(process.env.DATABASE_URL);
  if (fromUrl) return fromUrl;

  const dbName = String(process.env.DB_DATABASE || '').trim();
  const dbUser = String(process.env.DB_USERNAME || '').trim();
  const dbPass = String(process.env.DB_PASSWORD || '');

  if (!dbName || !dbUser) {
    throw new Error('Configuracao do banco ausente. Defina DATABASE_URL ou DB_DATABASE e DB_USERNAME.');
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

function parseJsonBody(request) {
  if (request.body && typeof request.body === 'object') {
    return request.body;
  }

  if (typeof request.body === 'string' && request.body.trim()) {
    try {
      return JSON.parse(request.body);
    } catch {
      return {};
    }
  }

  return {};
}

module.exports = async function handler(request, response) {
  if (request.method !== 'POST') {
    return response.status(405).json({ ok: false, message: 'Metodo nao permitido' });
  }

  try {
    const body = parseJsonBody(request);
    const nome = String(body.nome || '').trim();
    const turma = String(body.turma || '').trim();
    const turno = String(body.turno || '').trim();
    const motivo = String(body.motivo || '').trim();
    const dataEntrega = String(body.dataentrega || '').trim();
    const dataInicio = String(body.datainicio || '').trim();
    const horaInicio = String(body.horaInicio || '').trim();
    const diaInicio = String(body.diaInicio || '').trim();
    const dataTermino = String(body.datatermino || '').trim();
    const horaTermino = String(body.horaTermino || '').trim();
    const diaTermino = String(body.diaTermino || '').trim();

    if (!nome || !turma) {
      return response.status(400).json({ ok: false, message: 'Preencha ao menos nome e turma.' });
    }

    const pool = await getPool();
    const [result] = await pool.query(
      `INSERT INTO records (nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio, data_termino, hora_termino, dia_termino)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [nome, turma, turno, motivo, dataEntrega, dataInicio, horaInicio, diaInicio, dataTermino, horaTermino, diaTermino]
    );

    return response.status(201).json({
      ok: true,
      message: 'Dados salvos com sucesso!',
      id: Number(result.insertId)
    });
  } catch (error) {
    return response.status(500).json({ ok: false, message: error.message || 'Erro ao salvar no banco' });
  }
};
