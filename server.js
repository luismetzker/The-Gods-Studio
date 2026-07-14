'use strict';

require('dotenv').config();

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const DB_PATH = path.join(DATA_DIR, 'accounts.db');

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const SESSION_TTL = 1000 * 60 * 60 * 24 * 30;
const CAPTCHA_DIFFICULTY = 4;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_ENABLED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
const DB_SYNC_TOKEN = process.env.DB_SYNC_TOKEN || '';

const PROTECTED_PAGES = new Set(['/shop.html', '/aplicativos.html', '/contato.html']);

function getSecret() {
  const fromEnv = process.env.SESSION_SECRET;
  if (fromEnv && fromEnv.length >= 16) return fromEnv;
  try {
    const existing = fs.readFileSync(path.join(ROOT, '.session-secret'), 'utf8').trim();
    if (existing) return existing;
  } catch (_) {}
  const generated = crypto.randomBytes(48).toString('base64url');
  try {
    fs.writeFileSync(path.join(ROOT, '.session-secret'), generated, { mode: 0o600 });
  } catch (_) {}
  return generated;
}
const SECRET = getSecret();

let db;
function initDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(
    'CREATE TABLE IF NOT EXISTS users (' +
      'id TEXT PRIMARY KEY, ' +
      'username TEXT UNIQUE NOT NULL, ' +
      'email TEXT UNIQUE NOT NULL, ' +
      'passwordHash TEXT NOT NULL, ' +
      'provider TEXT NOT NULL DEFAULT \'local\', ' +
      'googleSub TEXT, ' +
      'createdAt INTEGER NOT NULL)'
  );
  try {
    const jsonPath = path.join(DATA_DIR, 'users.json');
    if (fs.existsSync(jsonPath)) {
      const arr = JSON.parse(fs.readFileSync(jsonPath, 'utf8')).users || [];
      const ins = db.prepare(
        'INSERT OR IGNORE INTO users (id,username,email,passwordHash,provider,googleSub,createdAt) VALUES (?,?,?,?,?,?,?)'
      );
      const tx = db.transaction((us) => {
        for (const u of us) {
          if (u && u.username && u.email) {
            ins.run(
              u.id || crypto.randomBytes(12).toString('hex'),
              String(u.username).toLowerCase(),
              String(u.email).toLowerCase(),
              u.passwordHash || '',
              u.provider || 'local',
              u.googleSub || null,
              u.createdAt || Date.now()
            );
          }
        }
      });
      tx(arr);
      try { fs.renameSync(jsonPath, jsonPath + '.migrated'); } catch (_) {}
    }
  } catch (e) {
    console.error('Falha na migração do JSON:', e);
  }
}

function rowToUser(r) {
  if (!r) return null;
  return {
    id: r.id,
    username: r.username,
    email: r.email,
    passwordHash: r.passwordHash,
    provider: r.provider,
    googleSub: r.googleSub,
    createdAt: r.createdAt,
  };
}
function findUserById(id) {
  return rowToUser(db.prepare('SELECT * FROM users WHERE id = ?').get(id));
}
function findByEmail(e) {
  return rowToUser(db.prepare('SELECT * FROM users WHERE email = ?').get(String(e).toLowerCase()));
}
function findByUsername(u) {
  return rowToUser(db.prepare('SELECT * FROM users WHERE username = ?').get(String(u).toLowerCase()));
}
function findByGoogle(sub) {
  return rowToUser(db.prepare('SELECT * FROM users WHERE googleSub = ?').get(sub));
}
function createUser(u) {
  db.prepare(
    'INSERT INTO users (id,username,email,passwordHash,provider,googleSub,createdAt) VALUES (?,?,?,?,?,?,?)'
  ).run(u.id, u.username.toLowerCase(), u.email.toLowerCase(), u.passwordHash, u.provider, u.googleSub || null, u.createdAt);
}
function updatePasswordHash(id, hash) {
  db.prepare('UPDATE users SET passwordHash = ? WHERE id = ?').run(hash, id);
}
function linkGoogle(id, sub) {
  db.prepare('UPDATE users SET googleSub = ? WHERE id = ?').run(sub, id);
}
function countUsers() {
  const row = db.prepare('SELECT COUNT(*) AS c FROM users').get();
  return row ? row.c : 0;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + derived.toString('hex');
}

function verifyPassword(password, stored) {
  if (typeof stored !== 'string' || !stored.startsWith('scrypt$')) return false;
  const parts = stored.split('$');
  if (parts.length !== 3) return false;
  const salt = Buffer.from(parts[1], 'hex');
  const expected = Buffer.from(parts[2], 'hex');
  const derived = crypto.scryptSync(password, salt, 64);
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

function base64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function signSession(uid) {
  const payload = base64url(JSON.stringify({ uid, iat: Date.now(), exp: Date.now() + SESSION_TTL }));
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return payload + '.' + sig;
}

function verifySession(token) {
  if (!token || typeof token !== 'string') return null;
  const idx = token.lastIndexOf('.');
  if (idx < 0) return null;
  const payload = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
  if (!data || typeof data.uid !== 'string' || !data.exp || data.exp < Date.now()) return null;
  return data;
}

const captchas = new Map();
function issueCaptcha() {
  const token = crypto.randomBytes(16).toString('hex');
  const challenge = crypto.randomBytes(16).toString('hex');
  captchas.set(token, { challenge, difficulty: CAPTCHA_DIFFICULTY, exp: Date.now() + 5 * 60 * 1000 });
  return { token, challenge, difficulty: CAPTCHA_DIFFICULTY };
}
function verifyCaptcha(token, nonce) {
  const c = captchas.get(token);
  if (!c) return false;
  if (c.exp < Date.now()) {
    captchas.delete(token);
    return false;
  }
  if (typeof nonce !== 'string' || !/^\d{1,12}$/.test(nonce)) return false;
  const h = crypto.createHash('sha256').update(c.challenge + ':' + nonce).digest('hex');
  const ok = h.startsWith('0'.repeat(c.difficulty));
  if (ok) captchas.delete(token);
  return ok;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of captchas) if (v.exp < now) captchas.delete(k);
}, 60 * 1000).unref();

const rateLimits = new Map();
function checkRateLimit(key, max, windowMs) {
  const now = Date.now();
  const rec = rateLimits.get(key);
  if (!rec || rec.reset < now) {
    rateLimits.set(key, { count: 1, reset: now + windowMs });
    return true;
  }
  rec.count++;
  return rec.count <= max;
}

const accountLocks = new Map();
function isLocked(key) {
  const until = accountLocks.get(key);
  return until && until > Date.now();
}
function lockAccount(key, ms) {
  accountLocks.set(key, Date.now() + ms);
}

function validUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_]{3,20}$/.test(u);
}
function validEmail(e) {
  return typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}
function validPassword(p) {
  return typeof p === 'string' && p.length >= 8 && p.length <= 128 && /[A-Za-z]/.test(p) && /\d/.test(p);
}

function userPublic(u) {
  return { id: u.id, username: u.username, email: u.email, provider: u.provider || 'local' };
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"
  );
  next();
});

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

function antiCsrf(req, res, next) {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    if (req.get('x-requested-with') !== 'xmlhttprequest') {
      return res.status(403).json({ error: 'Requisição inválida.' });
    }
  }
  next();
}
app.use(antiCsrf);

function parseCookies(req) {
  const header = req.get('cookie');
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function getUserFromReq(req) {
  const cookies = parseCookies(req);
  const data = verifySession(cookies.sid);
  if (!data) return null;
  return findUserById(data.uid) || null;
}

function setSessionCookie(res, uid) {
  res.cookie('sid', signSession(uid), {
    httpOnly: true,
    sameSite: 'lax',
    secure: NODE_ENV === 'production',
    path: '/',
    maxAge: SESSION_TTL,
  });
}
function clearSessionCookie(res) {
  res.cookie('sid', '', { httpOnly: true, sameSite: 'lax', secure: NODE_ENV === 'production', path: '/', maxAge: 0 });
}

const api = express.Router();

api.get('/config', (req, res) => {
  res.json({ googleEnabled: GOOGLE_ENABLED });
});

api.get('/captcha', (req, res) => {
  res.json(issueCaptcha());
});

api.get('/me', (req, res) => {
  const u = getUserFromReq(req);
  if (!u) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: userPublic(u) });
});

api.post('/signup', (req, res) => {
  try {
    const ip = req.ip;
    if (!checkRateLimit('signup:' + ip, 10, 15 * 60 * 1000)) {
      return res.status(429).json({ error: 'Muitas tentativas. Tente novamente mais tarde.' });
    }
    const body = req.body || {};
    const honeypot = body.hp;
    if (typeof honeypot === 'string' && honeypot.length > 0) {
      return res.status(400).json({ error: 'Cadastro inválido.' });
    }
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const confirm = typeof body.confirm === 'string' ? body.confirm : '';

    if (!validUsername(username)) {
      return res.status(400).json({ error: 'Nome de usuário deve ter 3 a 20 caracteres (letras, números ou _).' });
    }
    if (!validEmail(email)) {
      return res.status(400).json({ error: 'Informe um e-mail válido.' });
    }
    if (!validPassword(password)) {
      return res.status(400).json({ error: 'A senha precisa ter ao menos 8 caracteres, com letras e números.' });
    }
    if (password !== confirm) {
      return res.status(400).json({ error: 'As senhas não coincidem.' });
    }
    if (!verifyCaptcha(body.captchaToken, body.captchaNonce)) {
      return res.status(400).json({ error: 'Falha na verificação anti-bot. Tente novamente.' });
    }
    if (findByUsername(username)) {
      return res.status(409).json({ error: 'Este nome de usuário já está em uso.' });
    }
    if (findByEmail(email)) {
      return res.status(409).json({ error: 'Este e-mail já está cadastrado.' });
    }

    const user = {
      id: crypto.randomBytes(12).toString('hex'),
      username: username.toLowerCase(),
      email,
      passwordHash: hashPassword(password),
      provider: 'local',
      createdAt: Date.now(),
    };
    createUser(user);
    setSessionCookie(res, user.id);
    return res.json({ ok: true, user: userPublic(user) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }
});

api.post('/login', (req, res) => {
  try {
    const ip = req.ip;
    if (!checkRateLimit('login:' + ip, 20, 15 * 60 * 1000)) {
      return res.status(429).json({ error: 'Muitas tentativas. Tente novamente mais tarde.' });
    }
    const body = req.body || {};
    const honeypot = body.hp;
    if (typeof honeypot === 'string' && honeypot.length > 0) {
      return res.status(400).json({ error: 'Requisição inválida.' });
    }
    const identifier = typeof body.identifier === 'string' ? body.identifier.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (!identifier || !password) {
      return res.status(400).json({ error: 'Informe e-mail/usuário e senha.' });
    }

    const user = findByEmail(identifier) || findByUsername(identifier);
    if (!user || user.provider !== 'local') {
      return res.status(401).json({ error: 'E-mail ou senha inválidos.' });
    }
    const lockKey = 'acct:' + user.id;
    if (isLocked(lockKey)) {
      return res.status(429).json({ error: 'Conta temporariamente bloqueada por segurança. Tente mais tarde.' });
    }
    if (!verifyPassword(password, user.passwordHash)) {
      const fails = (accountLocks.get('fail:' + lockKey) || 0) + 1;
      if (fails >= 5) {
        accountLocks.set('fail:' + lockKey, 0);
        lockAccount(lockKey, 15 * 60 * 1000);
      } else {
        accountLocks.set('fail:' + lockKey, fails);
      }
      return res.status(401).json({ error: 'E-mail ou senha inválidos.' });
    }
    accountLocks.set('fail:' + lockKey, 0);
    setSessionCookie(res, user.id);
    return res.json({ ok: true, user: userPublic(user) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }
});

api.post('/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

api.post('/change-password', (req, res) => {
  try {
    const u = getUserFromReq(req);
    if (!u) return res.status(401).json({ error: 'Não autenticado.' });
    const body = req.body || {};
    const current = typeof body.current === 'string' ? body.current : '';
    const next = typeof body.next === 'string' ? body.next : '';
    if (!verifyPassword(current, u.passwordHash)) {
      return res.status(400).json({ error: 'Senha atual incorreta.' });
    }
    if (!validPassword(next)) {
      return res.status(400).json({ error: 'A nova senha precisa ter ao menos 8 caracteres, com letras e números.' });
    }
    updatePasswordHash(u.id, hashPassword(next));
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }
});

if (GOOGLE_ENABLED) {
  api.get('/auth/google/start', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    res.cookie('oauth_state', signSession('oauth:' + state), {
      httpOnly: true,
      sameSite: 'lax',
      secure: NODE_ENV === 'production',
      path: '/',
      maxAge: 10 * 60 * 1000,
    });
    const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/google/callback`;
    const url =
      'https://accounts.google.com/o/oauth2/v2/auth?' +
      new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        state,
        prompt: 'select_account',
      }).toString();
    res.redirect(url);
  });

  api.get('/auth/google/callback', async (req, res) => {
    try {
      const { code, state } = req.query;
      const cookies = parseCookies(req);
      const oauthCookie = verifySession(cookies.oauth_state);
      if (!oauthCookie || oauthCookie.uid !== 'oauth:' + state) {
        return res.status(403).send('Estado inválido.');
      }
      if (!code) return res.status(400).send('Código ausente.');
      const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/google/callback`;
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code',
        }).toString(),
      });
      const tokenJson = await tokenRes.json();
      if (!tokenJson.access_token) return res.status(400).send('Falha na autenticação.');
      const infoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${tokenJson.access_token}` },
      });
      const profile = await infoRes.json();
      if (!profile.sub || !profile.email) return res.status(400).send('Dados incompletos.');

      let user = findByGoogle(profile.sub);
      if (!user) {
        user = findByEmail(String(profile.email).toLowerCase());
        if (user && !user.googleSub) {
          linkGoogle(user.id, profile.sub);
        } else if (!user) {
          user = {
            id: crypto.randomBytes(12).toString('hex'),
            username: String(profile.email).split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 20) || 'user',
            email: String(profile.email).toLowerCase(),
            passwordHash: '',
            provider: 'google',
            googleSub: profile.sub,
            createdAt: Date.now(),
          };
          createUser(user);
        }
      }
      setSessionCookie(res, user.id);
      res.redirect('/');
    } catch (err) {
      console.error(err);
      res.status(500).send('Erro interno.');
    }
  });
}

app.use('/api', api);

if (DB_SYNC_TOKEN) {
  app.get('/api/db-info', (req, res) => {
    if (req.query.token !== DB_SYNC_TOKEN) return res.status(403).send('Forbidden');
    res.json({ users: countUsers() });
  });

  app.get('/api/db-backup', (req, res) => {
    if (req.query.token !== DB_SYNC_TOKEN) return res.status(403).send('Forbidden');
    try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch (_) {}
    if (!fs.existsSync(DB_PATH)) return res.status(404).send('No database');
    res.download(DB_PATH, 'accounts.db');
  });

  app.post('/api/db-backup', express.raw({ type: 'application/octet-stream', limit: '50mb' }), (req, res) => {
    if (req.query.token !== DB_SYNC_TOKEN) return res.status(403).send('Forbidden');
    if (!Buffer.isBuffer(req.body) || req.body.length < 100) return res.status(400).send('Invalid');
    try {
      try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch (_) {}
      fs.mkdirSync(path.join(DATA_DIR, 'backups'), { recursive: true });
      try { fs.copyFileSync(DB_PATH, path.join(DATA_DIR, 'backups', 'accounts-' + Date.now() + '.db')); } catch (_) {}
      try { db.close(); } catch (_) {}
      fs.writeFileSync(DB_PATH, req.body);
      initDb();
    } catch (e) {
      console.error('Falha ao restaurar db:', e);
      return res.status(500).send('Restore failed');
    }
    res.json({ ok: true });
  });
}

app.use((req, res, next) => {
  if (PROTECTED_PAGES.has(req.path)) {
    const u = getUserFromReq(req);
    if (!u) return res.redirect('/login.html?next=' + encodeURIComponent(req.path));
  }
  next();
});

app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

app.use((req, res) => {
  res.status(404).send('Página não encontrada.');
});

initDb();
app.listen(PORT, () => {
  console.log(`The Gods Studio rodando em http://localhost:${PORT} (env: ${NODE_ENV})`);
  console.log(`Login com Google: ${GOOGLE_ENABLED ? 'ativado' : 'desativado'}`);
  console.log(`Backup do banco: ${DB_SYNC_TOKEN ? 'ativado (token definido)' : 'desativado'}`);
});

module.exports = app;
