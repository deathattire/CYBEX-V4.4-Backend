'use strict';
// Self-test: starts the server on a temporary database and checks the security rules. Run: npm test
const { spawn } = require('node:child_process'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const PORT = 3999, BASE = `http://localhost:${PORT}`, ORIGIN = BASE;
const dbFile = path.join(os.tmpdir(), `cybex-test-${process.pid}.db`);
let pass = 0, fail = 0;
const t = (name, cond, extra = '') => { cond ? pass++ : fail++; console.log((cond ? 'PASS ' : 'FAIL ') + name + (cond ? '' : '  ' + extra)); };
class Client {
  constructor() { this.cookie = ''; this.csrf = ''; }
  async call(method, p, body, o = {}) {
    const h = { Accept: 'application/json' }; if (this.cookie) h.Cookie = this.cookie;
    if (!o.noOrigin) h.Origin = o.origin || ORIGIN; if (body !== undefined) h['Content-Type'] = 'application/json';
    if (method !== 'GET' && !o.noCsrf) h['X-CSRF-Token'] = o.csrf ?? this.csrf;
    const r = await fetch(BASE + p, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0];
    let d = {}; try { d = await r.json(); } catch {} if (d.csrf) this.csrf = d.csrf; return { s: r.status, d, h: r.headers };
  }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
// A tiny valid-looking JPEG with an EXIF (APP1) segment containing fake GPS text.
function jpeg(withExif) {
  const soi = Buffer.from([0xFF, 0xD8]), app1 = Buffer.concat([Buffer.from([0xFF, 0xE1, 0x00, 0x0D]), Buffer.from('GPS-SECRET!')]);
  const sof = Buffer.from([0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x80, 0x00, 0x80, 0x01, 0x01, 0x11, 0x00]);
  const sos = Buffer.from([0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x11, 0x22, 0xFF, 0xD9]);
  return Buffer.concat([soi, withExif ? app1 : Buffer.alloc(0), sof, sos]);
}
(async () => {
  const srv = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, 'server.js')], { env: { ...process.env, PORT: String(PORT), DB_PATH: dbFile, NODE_ENV: 'development', SITE_ORIGIN: ORIGIN, REGISTER_LIMIT: '100' }, stdio: ['ignore', 'pipe', 'inherit'] });
  for (let i = 0; i < 50; i++) { try { if ((await fetch(BASE + '/api/health')).ok) break; } catch {} await sleep(100); }
  try {
    const a = new Client(); let r;
    r = await a.call('GET', '/api/csrf'); t('csrf token issued with a cookie', r.s === 200 && a.csrf && a.cookie.startsWith('sid='));
    t('security headers on API', r.h.get('x-content-type-options') === 'nosniff' && r.h.get('cache-control') === 'no-store');
    r = await a.call('POST', '/api/register', { username: 'alice', password: 'correct horse battery' }, { noCsrf: true }); t('register without CSRF token is refused', r.s === 403 && r.d.code === 'csrf');
    r = await a.call('POST', '/api/register', { username: 'alice', password: 'correct horse battery' }, { origin: 'https://evil.example' }); t('wrong Origin is refused', r.s === 403 && r.d.code === 'origin');
    r = await a.call('POST', '/api/register', { username: 'alice', password: 'correct horse battery' }, { noOrigin: true }); t('missing Origin on POST is refused', r.s === 403);
    r = await a.call('POST', '/api/register', { username: 'admin', password: 'correct horse battery' }); t('reserved username refused', r.s === 400);
    r = await a.call('POST', '/api/register', { username: 'bob_1', password: 'short' }); t('short password refused', r.s === 400);
    r = await a.call('POST', '/api/register', { username: 'bob_1', password: 'password123' }); t('common password refused', r.s === 400);
    const oldCookie = a.cookie;
    r = await a.call('POST', '/api/register', { username: 'alice', displayName: '  Alice\u202E  ', password: 'correct horse battery', bio: 'hi', discoverable: true }); t('register works', r.s === 201 && r.d.user.username === 'alice' && r.d.user.displayName === 'Alice');
    t('session rotated after register', a.cookie !== oldCookie);
    const b = new Client(); await b.call('GET', '/api/csrf');
    r = await b.call('POST', '/api/register', { username: 'ALICE', password: 'another long password' }); t('duplicate username (any case) refused', r.s === 409);
    r = await b.call('POST', '/api/register', { username: 'bob_1', password: 'another long password', discoverable: false }); t('second user registers', r.s === 201);
    // login + session rotation + brute force
    const c = new Client(); await c.call('GET', '/api/csrf'); const pre = c.cookie;
    r = await c.call('POST', '/api/login', { username: 'alice', password: 'wrong password!!' }); t('wrong password gives generic 401', r.s === 401 && r.d.error === 'Invalid username or password.');
    r = await c.call('POST', '/api/login', { username: 'nobody_x', password: 'wrong password!!' }); t('unknown user gives the same message', r.s === 401 && r.d.error === 'Invalid username or password.');
    r = await c.call('POST', '/api/login', { username: 'alice', password: 'correct horse battery' }); t('login works', r.s === 200 && r.d.user.username === 'alice'); t('session rotated after login', c.cookie !== pre);
    const stale = new Client(); stale.cookie = pre; stale.csrf = 'x'; r = await stale.call('GET', '/api/me'); t('old session no longer works', r.s === 401);
    const bf = new Client(); await bf.call('GET', '/api/csrf'); let got429 = false;
    for (let i = 0; i < 10; i++) { r = await bf.call('POST', '/api/login', { username: 'alice', password: 'guess number ' + i + '!!' }); if (r.s === 429) { got429 = true; break; } }
    t('repeated wrong passwords are rate limited (429 + Retry-After)', got429 && !!r.h.get('retry-after'));
    // profile + pfp
    r = await c.call('GET', '/api/me'); t('GET /api/me returns user + csrf', r.s === 200 && r.d.csrf);
    r = await c.call('PUT', '/api/me', { displayName: 'Alice A', bio: 'Learning', pfp: 'https://tracker.example/x.png', discoverable: true }); t('remote picture URL refused', r.s === 400);
    r = await c.call('PUT', '/api/me', { displayName: 'Alice A', bio: 'Learning', pfp: 'data:image/png;base64,AAAA', discoverable: true }); t('non-JPEG picture refused', r.s === 400);
    const withExif = 'data:image/jpeg;base64,' + jpeg(true).toString('base64');
    r = await c.call('PUT', '/api/me', { displayName: 'Alice A', bio: 'Learning', pfp: withExif, discoverable: true });
    const saved = r.d.user && r.d.user.pfp ? Buffer.from(r.d.user.pfp.split(',')[1], 'base64') : Buffer.alloc(0);
    t('JPEG accepted and EXIF/GPS segment stripped', r.s === 200 && saved.length > 0 && !saved.includes(Buffer.from('GPS-SECRET')), r.s + ' ' + JSON.stringify(r.d).slice(0, 100));
    // progress
    r = await c.call('GET', '/api/progress'); t('new account has version 0', r.d.version === 0);
    r = await c.call('PUT', '/api/progress', { progress: { 'p0-0': true, 'p1-2': true }, baseVersion: 0 }); t('progress saved, version 1', r.s === 200 && r.d.version === 1);
    r = await c.call('PUT', '/api/progress', { progress: { 'p0-0': false }, baseVersion: 0 }); t('stale version gets 409', r.s === 409 && r.d.code === 'version');
    r = await c.call('PUT', '/api/progress', { progress: { '__proto__x': true }, baseVersion: 1 }); t('bad progress keys refused', r.s === 400);
    r = await c.call('PUT', '/api/progress', { progress: { 'p0-0': 'yes' }, baseVersion: 1 }); t('non-boolean progress values refused', r.s === 400);
    // privacy: search
    r = await b.call('GET', '/api/users?q=a'); t('search needs at least 2 characters', r.s === 400 || r.s === 401);
    r = await b.call('GET', '/api/users?q=al'); t('discoverable user is found, with progress %', r.s === 200 && r.d.users.some(u => u.username === 'alice' && u.progress === 3));
    r = await c.call('GET', '/api/users?q=bo'); t('non-discoverable user is hidden from search', r.s === 200 && r.d.users.length === 0);
    const anon = new Client(); await anon.call('GET', '/api/csrf'); r = await anon.call('GET', '/api/users?q=al'); t('search requires login', r.s === 401);
    // messaging
    r = await b.call('POST', '/api/messages', { to: 'alice', body: '<img src=x onerror=alert(1)> hello' }); t('message sent (stored as plain text)', r.s === 201);
    r = await b.call('POST', '/api/messages', { to: 'alice', body: 'again' }); t('second message within 5s is rate limited', r.s === 429);
    await sleep(5100); r = await b.call('POST', '/api/messages', { to: 'alice', body: 'one https://a.com two https://b.com' }); t('two links refused', r.s === 400);
    r = await b.call('POST', '/api/messages', { to: 'bob_1', body: 'hi me' }); t('cannot message yourself', r.s === 400);
    await sleep(5100); r = await b.call('POST', '/api/messages', { to: 'ghost_9', body: 'hi' }); t('unknown recipient gets 404', r.s === 404);
    r = await c.call('GET', '/api/messages'); const mid = r.d.messages && r.d.messages[0] && r.d.messages[0].id; t('recipient sees the message', r.s === 200 && r.d.messages.length === 1);
    r = await b.call('POST', '/api/messages/report', { messageId: mid }); t('only the recipient can report a message', r.s === 404);
    r = await c.call('POST', '/api/messages/report', { messageId: mid }); t('recipient can report', r.s === 200);
    r = await c.call('POST', '/api/blocks', { username: 'bob_1' }); t('block works', r.s === 200);
    r = await c.call('GET', '/api/messages'); t('blocked sender\'s messages are hidden', r.d.messages.length === 0);
    await sleep(5100); r = await b.call('POST', '/api/messages', { to: 'alice', body: 'after block' }); t('blocked sender is silently dropped (no error revealed)', r.s === 200 && r.d.ok);
    r = await c.call('GET', '/api/messages'); t('...and nothing was delivered', r.d.messages.length === 0);
    r = await b.call('GET', '/api/users?q=al'); t('blocked users vanish from each other\'s search', r.d.users.length === 0);
    r = await c.call('DELETE', '/api/blocks', { username: 'bob_1' }); t('unblock works', r.s === 200);
    // CSRF on logout + delete
    r = await c.call('POST', '/api/logout', undefined, { csrf: 'wrong' }); t('logout with a bad CSRF token is refused', r.s === 403);
    r = await c.call('DELETE', '/api/me', { password: 'not my password' }); t('delete account needs the right password', r.s === 403);
    r = await c.call('DELETE', '/api/me', { password: 'correct horse battery' }); t('account deleted', r.s === 200);
    const again = new Client(); await again.call('GET', '/api/csrf'); r = await again.call('POST', '/api/login', { username: 'alice', password: 'correct horse battery' }); t('deleted account cannot log in', r.s === 401 || r.s === 429);
    r = await b.call('GET', '/api/progress'); t('other users are unaffected by deletion', r.s === 200);
    r = await b.call('POST', '/api/logout'); t('logout works', r.s === 200); r = await b.call('GET', '/api/me'); t('after logout the session is dead', r.s === 401);
    // CORS + static
    const pre2 = await fetch(BASE + '/api/me', { method: 'OPTIONS', headers: { Origin: ORIGIN, 'Access-Control-Request-Method': 'PUT' } }); t('CORS preflight allows only the site origin', pre2.status === 204 && pre2.headers.get('access-control-allow-origin') === ORIGIN && pre2.headers.get('access-control-allow-credentials') === 'true');
    const bad = await fetch(BASE + '/api/me', { method: 'OPTIONS', headers: { Origin: 'https://evil.example' } }); t('CORS preflight from another origin is refused', bad.status === 403);
    for (const bp of ['/../server.js', '/%2e%2e/server.js', '/server.js', '/.env', '/package.json', '/index.html%00']) { const x = await fetch(BASE + bp); t('static file not exposed: ' + bp, x.status === 404); }
    const idx = await fetch(BASE + '/'); t('site is served at /', idx.status === 200 && (await idx.text()).includes('Cybex') && idx.headers.get('x-frame-options') === 'DENY');
    const cfg = await fetch(BASE + '/cybex-config.js'); t('config file points the site at this server', (await cfg.text()).includes('location.origin'));
    const big = await fetch(BASE + '/api/csrf'); t('health of server still fine after all tests', big.status === 200);
  } catch (e) { fail++; console.log('FAIL test crashed:', e); }
  srv.kill(); for (const x of ['', '-wal', '-shm']) try { fs.unlinkSync(dbFile + x); } catch {}
  console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})();
