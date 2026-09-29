'use strict';
// Cybex backend. No npm packages: only Node's built-in modules (Node 22.13 or newer).
const http = require('node:http'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// ---------- settings ----------
const PROD = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || (PROD ? '0.0.0.0' : '127.0.0.1');
const ORIGIN = (process.env.SITE_ORIGIN || (PROD ? '' : `http://localhost:${PORT}`)).replace(/\/$/, '');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'cybex.db');
const PUBLIC = path.join(__dirname, 'public');
const REGISTER_LIMIT = Number(process.env.REGISTER_LIMIT) || 5; // sign-ups per hour, per network address
const ROADMAP_TOTAL = 80; // number of roadmap checkboxes on the site
if (!ORIGIN) { console.error('SITE_ORIGIN is required in production, e.g. https://yourdomain.com'); process.exit(1); }
if (PROD && !/^https:\/\/[^/]+$/.test(ORIGIN)) { console.error('In production SITE_ORIGIN must be an https address with no path.'); process.exit(1); }
const SECURE = PROD, COOKIE = PROD ? '__Host-sid' : 'sid', SESSION_SECONDS = 7 * 86400;

// ---------- database ----------
const db = new DatabaseSync(DB_PATH);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL, bio TEXT NOT NULL DEFAULT '', pfp TEXT NOT NULL DEFAULT '', discoverable INTEGER NOT NULL DEFAULT 0, pass_hash TEXT NOT NULL, created_at INTEGER NOT NULL, suspended_until INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(sid_hash TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS progress(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, data TEXT NOT NULL, version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, from_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, to_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, body TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS msg_to ON messages(to_id, id); CREATE INDEX IF NOT EXISTS msg_from ON messages(from_id, created_at);
CREATE TABLE IF NOT EXISTS blocks(blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(blocker_id, blocked_id));
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, UNIQUE(message_id, reporter_id));`);
const P = s => db.prepare(s);
const S = {
  sess: P('SELECT * FROM sessions WHERE sid_hash=?'),
  insSess: P('INSERT INTO sessions(sid_hash,user_id,csrf,created_at,expires_at) VALUES(?,?,?,?,?)'),
  delSess: P('DELETE FROM sessions WHERE sid_hash=?'),
  purge: P('DELETE FROM sessions WHERE expires_at<?'),
  userById: P('SELECT * FROM users WHERE id=?'),
  userByName: P('SELECT * FROM users WHERE username=?'),
  insUser: P('INSERT INTO users(username,display_name,bio,pfp,discoverable,pass_hash,created_at) VALUES(?,?,?,?,?,?,?)'),
  updUser: P('UPDATE users SET display_name=?,bio=?,pfp=?,discoverable=? WHERE id=?'),
  delUser: P('DELETE FROM users WHERE id=?'),
  getProg: P('SELECT data,version FROM progress WHERE user_id=?'),
  putProg: P('INSERT INTO progress(user_id,data,version) VALUES(?,?,1) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, version=version+1 WHERE version=?'),
  insMsg: P('INSERT INTO messages(from_id,to_id,body,created_at) VALUES(?,?,?,?)'),
  msgs: P(`SELECT m.id,fu.username AS from_username,tu.username AS to_username,m.body,m.created_at FROM messages m JOIN users fu ON fu.id=m.from_id JOIN users tu ON tu.id=m.to_id WHERE (m.from_id=?1 OR m.to_id=?1) AND NOT EXISTS(SELECT 1 FROM blocks b WHERE b.blocker_id=?1 AND b.blocked_id=m.from_id) ORDER BY m.id DESC LIMIT 100`),
  msgById: P('SELECT * FROM messages WHERE id=?'),
  isBlocked: P('SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?'),
  block: P('INSERT OR IGNORE INTO blocks(blocker_id,blocked_id) VALUES(?,?)'),
  unblock: P('DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?'),
  sentSince: P('SELECT COUNT(*) c, COUNT(DISTINCT to_id) d, SUM(to_id=?2) t FROM messages WHERE from_id=?1 AND created_at>?3'),
  dup: P('SELECT 1 FROM messages WHERE from_id=? AND body=? AND created_at>?'),
  report: P('INSERT OR IGNORE INTO reports(message_id,reporter_id,created_at) VALUES(?,?,?)'),
  reporters: P('SELECT COUNT(DISTINCT r.reporter_id) c FROM reports r JOIN messages m ON m.id=r.message_id WHERE m.from_id=? AND r.created_at>?'),
  suspend: P('UPDATE users SET suspended_until=? WHERE id=?'),
  search: P(`SELECT u.username,u.display_name,u.bio,u.pfp,p.data FROM users u LEFT JOIN progress p ON p.user_id=u.id WHERE u.discoverable=1 AND u.id!=?1 AND (u.username LIKE ?2 ESCAPE '\\' OR u.display_name LIKE ?2 ESCAPE '\\') AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker_id=?1 AND b.blocked_id=u.id) OR (b.blocker_id=u.id AND b.blocked_id=?1)) ORDER BY u.username LIMIT 20`),
};

// ---------- small helpers ----------
class HttpError extends Error { constructor(status, msg, code, retry) { super(msg); this.status = status; this.code = code; this.retry = retry; } }
const now = () => Math.floor(Date.now() / 1000);
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const log = (evt, o = {}) => console.log(JSON.stringify({ t: new Date().toISOString(), evt, ...o }));
const USER_RE = /^[A-Za-z0-9_]{3,24}$/, CHK_RE = /^[pjrbcfag]\d{1,2}-\d{1,3}$/;
const RESERVED = new Set(['admin', 'administrator', 'root', 'support', 'cybex', 'moderator', 'mod', 'system', 'null', 'undefined', 'staff', 'security', 'help', 'api']);
const COMMON = new Set(['password123', 'passw0rd123', '1234567890', 'qwertyuiop', 'iloveyou123', 'letmein1234', 'welcome1234', 'administrator', 'password1234', 'changeme123', 'qwerty12345', '0123456789', 'abcdefghij']);
const clean = (s, max) => String(s ?? '').replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '').trim().slice(0, max);
const cleanMsg = s => String(s ?? '').replace(/[\u0000-\u0009\u000b-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '').trim();
const ipOf = req => { let a = req.socket.remoteAddress || ''; if (TRUST_PROXY) { const x = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean); if (x.length) a = x[x.length - 1]; } return a; };

// Sliding-window rate limiter (in memory: resets on restart, one server only).
const hits = new Map();
function rl(key, max, seconds, msg) {
  const t = Date.now(), w = seconds * 1000, a = (hits.get(key) || []).filter(x => t - x < w);
  if (a.length >= max) { hits.set(key, a); throw new HttpError(429, msg || 'Too many requests. Please wait a moment.', 'rate', Math.max(1, Math.ceil((w - (t - a[0])) / 1000))); }
  a.push(t); hits.set(key, a);
}
setInterval(() => { const t = Date.now(); for (const [k, a] of hits) if (!a.length || t - a[a.length - 1] > 86400000) hits.delete(k); S.purge.run(now()); }, 600000).unref();

// ---------- passwords (scrypt, memory-hard) ----------
const scrypt = (pw, salt, N, r, p) => new Promise((ok, bad) => crypto.scrypt(pw, salt, 64, { N, r, p, maxmem: 128 * 1024 * 1024 }, (e, k) => e ? bad(e) : ok(k)));
async function hashPw(pw) { const salt = crypto.randomBytes(16); const k = await scrypt(pw.normalize('NFKC'), salt, 16384, 8, 1); return `scrypt$16384$8$1$${salt.toString('base64')}$${k.toString('base64')}`; }
async function checkPw(pw, stored) {
  const p = String(stored).split('$'); if (p[0] !== 'scrypt' || p.length !== 6) return false;
  const k = await scrypt(pw.normalize('NFKC'), Buffer.from(p[4], 'base64'), +p[1], +p[2], +p[3]), want = Buffer.from(p[5], 'base64');
  return k.length === want.length && crypto.timingSafeEqual(k, want);
}
let DUMMY = ''; hashPw('dummy-password-for-timing').then(h => { DUMMY = h; });
function pwPolicy(pw, un) {
  if (pw.length < 10 || pw.length > 128) throw new HttpError(400, 'Password must be 10 to 128 characters.');
  if (COMMON.has(pw.toLowerCase()) || pw.toLowerCase().includes(un.toLowerCase())) throw new HttpError(400, 'That password is too easy to guess. Choose another.');
}

// ---------- profile pictures: JPEG only, metadata removed ----------
function cleanPfp(v) {
  if (v === '' || v == null) return '';
  const bad = () => new HttpError(400, 'Profile picture must be a small JPEG (128 px is ideal).');
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/.exec(String(v)); if (!m || m[1].length > 56000) throw bad();
  const b = Buffer.from(m[1], 'base64'); if (b.length < 8 || b[0] !== 0xFF || b[1] !== 0xD8) throw bad();
  const out = [b.subarray(0, 2)]; let i = 2, w = 0, h = 0, ok = false;
  while (i + 4 <= b.length) {
    if (b[i] !== 0xFF) throw bad(); const mk = b[i + 1]; if (mk === 0xFF) { i++; continue; } if (mk === 0xD9) break;
    const len = b.readUInt16BE(i + 2); if (len < 2 || i + 2 + len > b.length) throw bad();
    if (mk === 0xDA) { out.push(b.subarray(i)); ok = true; break; }
    if (mk >= 0xC0 && mk <= 0xC3 && len >= 8) { h = b.readUInt16BE(i + 5); w = b.readUInt16BE(i + 7); }
    if (!((mk >= 0xE1 && mk <= 0xEF) || mk === 0xFE)) out.push(b.subarray(i, i + 2 + len)); // drops EXIF, GPS and comments
    i += 2 + len;
  }
  if (!ok || !w || !h || w > 256 || h > 256) throw bad();
  return 'data:image/jpeg;base64,' + Buffer.concat(out).toString('base64');
}

// ---------- sessions and CSRF ----------
function cookiesOf(req) { const o = {}; String(req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }); return o; }
function getSession(req) { const sid = cookiesOf(req)[COOKIE]; if (!/^[A-Za-z0-9_-]{43}$/.test(sid || '')) return null; const r = S.sess.get(sha(sid)); return r && r.expires_at > now() ? { ...r, sid } : null; }
function newSession(res, userId) {
  const sid = crypto.randomBytes(32).toString('base64url'), csrf = crypto.randomBytes(24).toString('base64url');
  S.insSess.run(sha(sid), userId, csrf, now(), now() + SESSION_SECONDS);
  res.setHeader('Set-Cookie', `${COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_SECONDS}${SECURE ? '; Secure' : ''}`);
  return csrf;
}
const clearCookie = res => res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${SECURE ? '; Secure' : ''}`);

// ---------- shapes ----------
const pct = data => { try { const o = JSON.parse(data || '{}'); return Math.min(100, Math.round(Object.entries(o).filter(([k, v]) => v === true && k[0] === 'p').length / ROADMAP_TOTAL * 100)); } catch { return 0; } };
const publicUser = (u, prog) => ({ username: u.username, displayName: u.display_name, bio: u.bio, pfp: u.pfp, progress: pct(prog ?? (S.getProg.get(u.id) || {}).data), discoverable: !!u.discoverable });

// ---------- API ----------
async function api(ctx) {
  const { req, res, url, body, sess, ip } = ctx, m = req.method, p = url.pathname;
  const user = sess && sess.user_id ? S.userById.get(sess.user_id) : null;
  const need = () => { if (!user) throw new HttpError(401, 'Please log in.'); return user; };
  const ok = (o, s = 200) => ({ s, o });

  if (p === '/api/health' && m === 'GET') return ok({ ok: true });
  if (p === '/api/csrf' && m === 'GET') {
    rl('csrf:' + ip, 60, 60);
    if (sess) return ok({ csrf: sess.csrf });
    return ok({ csrf: newSession(res, null) });
  }
  if (p === '/api/register' && m === 'POST') {
    rl('reg:' + ip, REGISTER_LIMIT, 3600, 'Too many sign-ups from this network. Try again later.');
    const un = String(body.username || ''); if (!USER_RE.test(un) || RESERVED.has(un.toLowerCase())) throw new HttpError(400, 'Username must be 3 to 24 letters, numbers or underscores.');
    const pw = String(body.password || ''); pwPolicy(pw, un);
    const dn = clean(body.displayName, 32) || un, bio = clean(body.bio, 160) || 'Cybersecurity learner', pfp = cleanPfp(body.pfp), disc = body.discoverable === true ? 1 : 0;
    const hash = await hashPw(pw); let id;
    try { id = Number(S.insUser.run(un, dn, bio, pfp, disc, hash, now()).lastInsertRowid); } catch (e) { if (/UNIQUE/.test(e.message)) throw new HttpError(409, 'That username is unavailable.'); throw e; }
    S.delSess.run(sha(sess.sid)); const csrf = newSession(res, id); log('register', { u: id });
    return ok({ user: publicUser(S.userById.get(id)), csrf }, 201);
  }
  if (p === '/api/login' && m === 'POST') {
    const un = String(body.username || ''), pw = String(body.password || '');
    rl('login-ip:' + ip, 20, 900, 'Too many login attempts. Try again in a few minutes.');
    rl('login-user:' + un.toLowerCase().slice(0, 24), 8, 900, 'Too many login attempts for this account. Try again in a few minutes.');
    if (!USER_RE.test(un) || !pw || pw.length > 128) throw new HttpError(401, 'Invalid username or password.');
    const u = S.userByName.get(un), good = await checkPw(pw, u ? u.pass_hash : DUMMY);
    if (!u || !good) { log('login_fail', { ip: sha(ip).slice(0, 8) }); throw new HttpError(401, 'Invalid username or password.'); }
    S.delSess.run(sha(sess.sid)); const csrf = newSession(res, u.id); log('login', { u: u.id });
    return ok({ user: publicUser(u), csrf });
  }
  if (p === '/api/logout' && m === 'POST') { S.delSess.run(sha(sess.sid)); clearCookie(res); return ok({ ok: true }); }
  if (p === '/api/me' && m === 'GET') { need(); return ok({ user: publicUser(user), csrf: sess.csrf }); }
  if (p === '/api/me' && m === 'PUT') {
    need(); rl('me:' + user.id, 20, 60);
    const dn = clean(body.displayName, 32) || user.username, bio = clean(body.bio, 160) || 'Cybersecurity learner';
    const pfp = body.pfp === undefined ? user.pfp : cleanPfp(body.pfp), disc = body.discoverable === undefined ? user.discoverable : (body.discoverable === true ? 1 : 0);
    S.updUser.run(dn, bio, pfp, disc, user.id); return ok({ user: publicUser(S.userById.get(user.id)) });
  }
  if (p === '/api/me' && m === 'DELETE') {
    need(); rl('del:' + user.id, 5, 3600);
    if (!(await checkPw(String(body.password || ''), user.pass_hash))) throw new HttpError(403, 'Password is incorrect.');
    S.delUser.run(user.id); clearCookie(res); log('delete_account', { u: user.id }); return ok({ ok: true });
  }
  if (p === '/api/progress' && m === 'GET') { need(); const r = S.getProg.get(user.id); return ok({ progress: r ? JSON.parse(r.data) : {}, version: r ? r.version : 0 }); }
  if (p === '/api/progress' && m === 'PUT') {
    need(); rl('prog:' + user.id, 30, 60);
    const pr = body.progress, keys = pr && typeof pr === 'object' && !Array.isArray(pr) ? Object.keys(pr) : null;
    if (!keys || keys.length > 600 || keys.some(k => !CHK_RE.test(k) || typeof pr[k] !== 'boolean')) throw new HttpError(400, 'Invalid progress data.');
    const r = S.getProg.get(user.id), cur = r ? r.version : 0;
    if (!Number.isInteger(body.baseVersion) || body.baseVersion !== cur) throw new HttpError(409, 'Your progress changed elsewhere. Syncing now.', 'version');
    const clean2 = {}; keys.forEach(k => { clean2[k] = pr[k]; });
    if (!S.putProg.run(user.id, JSON.stringify(clean2), cur).changes) throw new HttpError(409, 'Your progress changed elsewhere. Syncing now.', 'version');
    return ok({ version: cur + 1 });
  }
  if (p === '/api/users' && m === 'GET') {
    need(); rl('search:' + user.id, 30, 60, 'You are searching too fast.');
    const q = clean(url.searchParams.get('q'), 24); if (q.length < 2) throw new HttpError(400, 'Type at least 2 characters.');
    const rows = S.search.all(user.id, q.replace(/[\\%_]/g, '\\$&') + '%');
    return ok({ users: rows.map(r => ({ username: r.username, displayName: r.display_name, bio: r.bio, pfp: r.pfp, progress: pct(r.data), discoverable: true })) });
  }
  if (p === '/api/messages' && m === 'GET') {
    need(); rl('inbox:' + user.id, 60, 60);
    return ok({ messages: S.msgs.all(user.id).map(r => ({ ...r, created_at: new Date(r.created_at * 1000).toISOString() })) });
  }
  if (p === '/api/messages' && m === 'POST') {
    need(); const to = String(body.to || ''), text = cleanMsg(body.body);
    if (!USER_RE.test(to)) throw new HttpError(400, 'Enter a valid recipient username.');
    if (!text) throw new HttpError(400, 'Write a message first.'); if (text.length > 1000) throw new HttpError(400, 'Messages can be at most 1000 characters.');
    if ((text.match(/https?:\/\/|www\./gi) || []).length > 1) throw new HttpError(400, 'Messages can contain at most one link.');
    if (user.suspended_until > now()) throw new HttpError(403, 'Messaging is temporarily disabled on your account.');
    rl('m5:' + user.id, 1, 5, 'Please wait a few seconds before sending another message.'); rl('m60:' + user.id, 6, 60, 'You are sending messages too quickly. Try again in a minute.');
    const target = S.userByName.get(to); if (!target) throw new HttpError(404, 'Recipient not found.');
    if (target.id === user.id) throw new HttpError(400, 'You cannot message yourself.');
    if (S.isBlocked.get(target.id, user.id)) return ok({ ok: true }); // silently dropped: the sender is not told they were blocked
    const day = S.sentSince.get(user.id, target.id, now() - 86400), fresh = now() - user.created_at < 172800;
    if (day.c >= (fresh ? 20 : 200)) throw new HttpError(429, 'Daily message limit reached.', 'rate', 3600);
    if (fresh && day.d >= 5 && !day.t) throw new HttpError(429, 'New accounts can message up to 5 different people per day.', 'rate', 3600);
    if (S.dup.get(user.id, text, now() - 60)) throw new HttpError(409, 'That looks like a duplicate of your last message.');
    S.insMsg.run(user.id, target.id, text, now()); return ok({ ok: true }, 201);
  }
  if (p === '/api/messages/report' && m === 'POST') {
    need(); rl('report:' + user.id, 10, 3600);
    const msg = Number.isInteger(body.messageId) ? S.msgById.get(body.messageId) : null;
    if (!msg || msg.to_id !== user.id) throw new HttpError(404, 'Message not found.');
    S.report.run(msg.id, user.id, now());
    if (S.reporters.get(msg.from_id, now() - 7 * 86400).c >= 3) { S.suspend.run(now() + 72 * 3600, msg.from_id); log('auto_suspend', { u: msg.from_id }); }
    return ok({ ok: true });
  }
  if (p === '/api/blocks' && (m === 'POST' || m === 'DELETE')) {
    need(); rl('block:' + user.id, 30, 3600);
    const t = USER_RE.test(String(body.username || '')) ? S.userByName.get(String(body.username)) : null;
    if (!t || t.id === user.id) throw new HttpError(404, 'User not found.');
    (m === 'POST' ? S.block : S.unblock).run(user.id, t.id); return ok({ ok: true });
  }
  throw new HttpError(404, 'Not found.');
}

// ---------- request handling ----------
function baseHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'); res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (SECURE) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function send(res, status, obj, retry) {
  const b = JSON.stringify(obj); res.statusCode = status; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'"); if (retry) res.setHeader('Retry-After', String(retry)); res.end(b);
}
function readBody(req) {
  return new Promise((ok, bad) => {
    let n = 0; const c = [];
    req.on('data', d => { n += d.length; if (n > 98304) { bad(new HttpError(413, 'Request too large.')); req.destroy(); } else c.push(d); });
    req.on('end', () => {
      if (!n) return ok({});
      if (!/^application\/json/i.test(req.headers['content-type'] || '')) return bad(new HttpError(415, 'Send JSON.'));
      try { const o = JSON.parse(Buffer.concat(c).toString('utf8')); ok(o && typeof o === 'object' && !Array.isArray(o) ? o : {}); } catch { bad(new HttpError(400, 'Invalid JSON.')); }
    });
    req.on('error', () => bad(new HttpError(400, 'Bad request.')));
  });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };
function serveStatic(req, res, p) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.statusCode = 405; return res.end(); }
  if (p === '/cybex-config.js') { res.setHeader('Content-Type', MIME['.js']); res.setHeader('Cache-Control', 'no-cache'); return res.end('window.CYBEX_API_BASE = location.origin;\n'); }
  const name = p === '/' ? 'index.html' : p.slice(1), ext = path.extname(name);
  if (!/^[A-Za-z0-9._-]+$/.test(name) || name.startsWith('.') || !MIME[ext]) { res.statusCode = 404; return res.end('Not found'); }
  const file = path.join(PUBLIC, name);
  if (!file.startsWith(PUBLIC + path.sep) || !fs.existsSync(file)) { res.statusCode = 404; return res.end('Not found'); }
  res.setHeader('Content-Type', MIME[ext]); res.setHeader('Cache-Control', 'no-cache'); res.setHeader('Content-Security-Policy', "frame-ancestors 'none'"); res.end(fs.readFileSync(file));
}
const server = http.createServer(async (req, res) => {
  baseHeaders(res);
  try {
    const url = new URL(req.url, 'http://x'), ip = ipOf(req);
    if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
    const origin = req.headers.origin, method = req.method;
    if (origin) {
      if (origin !== ORIGIN) throw new HttpError(403, 'Origin not allowed.', 'origin');
      res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Access-Control-Allow-Credentials', 'true'); res.setHeader('Vary', 'Origin');
    }
    if (method === 'OPTIONS') { res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE'); res.setHeader('Access-Control-Allow-Headers', 'content-type,x-csrf-token,accept'); res.setHeader('Access-Control-Max-Age', '600'); res.statusCode = 204; return res.end(); }
    if (!['GET', 'POST', 'PUT', 'DELETE'].includes(method)) throw new HttpError(405, 'Method not allowed.');
    rl('ip:' + ip, 300, 60);
    const write = method !== 'GET';
    if (write && !origin) throw new HttpError(403, 'Origin required.', 'origin');
    const body = write ? await readBody(req) : {};
    let sess = getSession(req);
    if (write) {
      const tok = String(req.headers['x-csrf-token'] || ''), a = Buffer.from(tok), b = Buffer.from(sess ? sess.csrf : '');
      if (!sess || a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new HttpError(403, 'Security token expired. Please try again.', 'csrf');
    }
    const r = await api({ req, res, url, body, sess, ip });
    send(res, r.s, r.o);
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message, ...(e.code ? { code: e.code } : {}) }, e.retry);
    log('error', { msg: String(e && e.message).slice(0, 200) }); send(res, 500, { error: 'Something went wrong.' });
  }
});
server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000;
server.listen(PORT, HOST, () => log('listening', { host: HOST, port: PORT, origin: ORIGIN, prod: PROD }));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => { db.close(); process.exit(0); }));
