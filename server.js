// Tiny password-gated static server. No dependencies.
// Env: SITE_PASSWORD (required), COOKIE_SECRET (recommended), PORT (set by Render)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.SITE_PASSWORD;
const SECRET = process.env.COOKIE_SECRET || PASSWORD;
if (!PASSWORD) {
  console.error('SITE_PASSWORD is not set');
  process.exit(1);
}

const ROOT = path.join(__dirname, 'private');
const COOKIE = 'kb_auth';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.gif': 'image/gif', '.ico': 'image/x-icon', '.webp': 'image/webp',
  '.csv': 'text/csv', '.txt': 'text/plain; charset=utf-8', '.woff2': 'font/woff2',
};

const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const safeEq = (a, b) => {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
};
const makeToken = () => {
  const exp = Date.now() + MAX_AGE * 1000;
  return `${exp}.${sign(String(exp))}`;
};
const validToken = (t) => {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  return !!sig && Number(exp) > Date.now() && safeEq(sig, sign(exp));
};
const cookies = (req) =>
  Object.fromEntries(
    (req.headers.cookie || '').split(';').map((c) => {
      const i = c.indexOf('=');
      return i < 0 ? ['', ''] : [c.slice(0, i).trim(), c.slice(i + 1).trim()];
    })
  );

// crude brute-force limiter: 8 failures per 15 min per IP
const WINDOW = 15 * 60 * 1000;
const fails = new Map();
const blocked = (ip) => {
  const f = fails.get(ip);
  return f && f.n >= 8 && Date.now() - f.t < WINDOW;
};
const noteFail = (ip) => {
  const f = fails.get(ip);
  fails.set(ip, { n: (f && Date.now() - f.t < WINDOW ? f.n : 0) + 1, t: Date.now() });
};

const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const loginPage = (err) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Enter password</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#0f1115;color:#e8e8e8}
form{display:flex;flex-direction:column;gap:12px;width:min(320px,86vw)}
input,button{padding:12px;border-radius:8px;border:1px solid #333;font-size:16px}
input{background:#1a1d24;color:#fff}button{background:#4f7cff;color:#fff;border:0;cursor:pointer}
p{color:#ff6b6b;margin:0;font-size:14px}</style></head><body>
<form method="POST" action="/login"><input type="password" name="password" placeholder="Password" autofocus required>
<button>Enter</button>${err ? `<p>${esc(err)}</p>` : ''}</form></body></html>`;

const indexPage = () => {
  const files = [];
  (function walk(d, rel) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(path.join(d, e.name), r);
      else if (e.name.endsWith('.html') && r !== 'index.html') files.push(r);
    }
  })(ROOT, '');
  const items = files
    .sort()
    .map((f) => `<li><a href="/${encodeURI(f)}">${esc(f.replace(/\.html$/, ''))}</a></li>`)
    .join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Dashboards</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e8e8e8;max-width:640px;margin:48px auto;padding:0 16px}
a{color:#7da2ff;font-size:18px;line-height:2}</style></head><body><h1>Dashboards</h1>
<ul>${items || '<li>Nothing here yet. Drop .html files in /private.</li>'}</ul>
<p><a href="/logout" style="font-size:14px">Log out</a></p></body></html>`;
};

http
  .createServer((req, res) => {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const url = new URL(req.url, 'http://x');
    const send = (code, type, body, extra = {}) => {
      res.writeHead(code, {
        'Content-Type': type,
        'X-Robots-Tag': 'noindex',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        ...extra,
      });
      res.end(body);
    };

    if (url.pathname === '/healthz') return send(200, 'text/plain', 'ok');

    if (url.pathname === '/login' && req.method === 'POST') {
      if (blocked(ip)) return send(429, 'text/html; charset=utf-8', loginPage('Too many attempts, try later.'));
      let body = '';
      req.on('data', (c) => {
        body += c;
        if (body.length > 4096) req.destroy();
      });
      req.on('end', () => {
        const pw = new URLSearchParams(body).get('password') || '';
        if (safeEq(pw, PASSWORD)) {
          fails.delete(ip);
          return send(302, 'text/plain', '', {
            Location: '/',
            'Set-Cookie': `${COOKIE}=${makeToken()}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${MAX_AGE}`,
          });
        }
        noteFail(ip);
        send(401, 'text/html; charset=utf-8', loginPage('Wrong password.'));
      });
      return;
    }

    if (url.pathname === '/logout') {
      return send(302, 'text/plain', '', {
        Location: '/',
        'Set-Cookie': `${COOKIE}=; HttpOnly; Secure; Path=/; Max-Age=0`,
      });
    }

    if (!validToken(cookies(req)[COOKIE])) {
      return send(200, 'text/html; charset=utf-8', loginPage(), { 'Cache-Control': 'no-store' });
    }

    let rel;
    try {
      rel = decodeURIComponent(url.pathname);
    } catch {
      return send(400, 'text/plain', 'Bad request');
    }
    let file = path.join(ROOT, rel);
    if (file !== ROOT && !file.startsWith(ROOT + path.sep)) return send(403, 'text/plain', 'Forbidden');
    if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
    if (rel === '/' && !fs.existsSync(file)) {
      return send(200, 'text/html; charset=utf-8', indexPage(), { 'Cache-Control': 'no-store' });
    }
    if (!fs.existsSync(file)) return send(404, 'text/plain', 'Not found');
    send(200, TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream', fs.readFileSync(file), {
      'Cache-Control': 'private, no-cache',
    });
  })
  .listen(PORT, () => console.log(`Listening on ${PORT}`));
