/**
 * GLOBAL AUTH WORKER
 * Centralized login, register, logout for all 111iridescence.org apps.
 * Route: 111iridescence.org/auth*
 *
 * Endpoints:
 *   GET  /auth/login    → render login/register page
 *   POST /auth/login    → authenticate, set cookie, redirect to ?redirect param
 *   POST /auth/register → create account, redirect to login
 *   GET  /auth/logout   → clear session cookie, redirect to /
 */

const SESSION_TTL_MS = 2592000000; // 30 days in milliseconds
const COOKIE_MAX_AGE = 2592000;    // 30 days in seconds

export default {
    async fetch(req, env) {
        const url = new URL(req.url);
        let path = url.pathname;

        // Normalize: strip /auth prefix
        if (path.startsWith('/auth')) {
            path = path.substring(5) || '/';
        }

        // POST /login — authenticate user
        if (path === '/login' && req.method === 'POST') {
            const fd = await req.formData();
            const username = fd.get('u');
            const password = fd.get('p');
            const redirect = fd.get('redirect') || '/';

            const dbUser = await env.AUTH_DB
                .prepare('SELECT * FROM users WHERE username = ? AND password = ?')
                .bind(username, await hash(password))
                .first();

            if (!dbUser) {
                // Re-render login page with error
                return new Response(renderLogin(redirect, 'Invalid username or password.'), {
                    status: 401,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            const sessId = crypto.randomUUID();
            await env.AUTH_DB
                .prepare('INSERT INTO sessions (id, username, role, expires) VALUES (?, ?, ?, ?)')
                .bind(sessId, dbUser.username, dbUser.role, Date.now() + SESSION_TTL_MS)
                .run();

            return new Response(null, {
                status: 302,
                headers: {
                    'Location': redirect || '/',
                    'Set-Cookie': `sess=${sessId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${COOKIE_MAX_AGE}`
                }
            });
        }

        // POST /register — create new account
        if (path === '/register' && req.method === 'POST') {
            const fd = await req.formData();
            const username = fd.get('u');
            const password = fd.get('p');
            const redirect = fd.get('redirect') || '/';

            if (!username || username.length < 3) {
                return new Response(renderLogin(redirect, 'Username must be at least 3 characters.', true), {
                    status: 400,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            const existing = await env.AUTH_DB
                .prepare('SELECT username FROM users WHERE username = ?')
                .bind(username)
                .first();

            if (existing) {
                return new Response(renderLogin(redirect, 'Username already taken.', true), {
                    status: 400,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            await env.AUTH_DB
                .prepare('INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)')
                .bind(username, await hash(password), 'user', Date.now())
                .run();

            // Redirect to login with success message
            const loginUrl = `/auth/login?redirect=${encodeURIComponent(redirect)}&registered=1`;
            return new Response(null, { status: 302, headers: { 'Location': loginUrl } });
        }

        // GET /logout — clear session
        if (path === '/logout') {
            const cookie = req.headers.get('Cookie');
            const sessId = cookie
                ? cookie.split(';').find(c => c.trim().startsWith('sess='))?.split('=')[1]
                : null;

            if (sessId) {
                await env.AUTH_DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessId).run();
            }

            // Redirect to home (the hub page)
            return new Response(null, {
                status: 302,
                headers: {
                    'Location': '/',
                    'Set-Cookie': 'sess=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
                }
            });
        }

        // GET /login — render login page
        if (path === '/login' || path === '/') {
            const redirect = url.searchParams.get('redirect') || '/';
            const registered = url.searchParams.get('registered') === '1';
            const msg = registered ? 'Account created! You can now log in.' : '';
            return new Response(renderLogin(redirect, msg, false, registered), {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }

        return new Response('Not found', { status: 404 });
    }
};

async function hash(str) {
    const buf = new TextEncoder().encode(str);
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buf)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

const CSS = `
:root{--bg:#121212;--card:#1e1e1e;--txt:#e0e0e0;--p:#bb86fc;--s:#03dac6;--err:#cf6679;--good:#4caf50}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--txt);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:var(--card);padding:30px;border-radius:12px;border:1px solid #2a2a2a;width:100%;max-width:360px;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
h2{text-align:center;margin-bottom:6px;font-size:1.4em}
.subtitle{text-align:center;color:#777;font-size:0.85em;margin-bottom:24px}
label{display:block;font-size:0.82em;color:#aaa;margin-bottom:4px;margin-top:14px}
input{background:#2a2a2a;border:1px solid #3a3a3a;color:#fff;padding:10px 12px;border-radius:6px;width:100%;font-size:0.95em;transition:border-color 0.2s}
input:focus{outline:none;border-color:var(--p)}
.btn{cursor:pointer;border:none;padding:11px;border-radius:6px;width:100%;font-weight:700;font-size:0.95em;transition:opacity 0.15s;margin-top:16px}
.btn-primary{background:var(--p);color:#000}
.btn-secondary{background:#2a2a2a;color:#aaa;border:1px solid #3a3a3a;margin-top:10px}
.btn:hover{opacity:0.85}
.msg{text-align:center;font-size:0.85em;padding:8px;border-radius:6px;margin-top:14px}
.msg.err{color:var(--err);background:rgba(207,102,121,0.1)}
.msg.ok{color:var(--good);background:rgba(76,175,80,0.1)}
.divider{text-align:center;color:#444;font-size:0.8em;margin:18px 0;position:relative}
.divider::before,.divider::after{content:'';position:absolute;top:50%;width:42%;height:1px;background:#2a2a2a}
.divider::before{left:0}.divider::after{right:0}
`;

function renderLogin(redirect = '/', statusMsg = '', showReg = false, isSuccess = false) {
    const enc = encodeURIComponent(redirect);
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${showReg ? 'Create Account' : 'Sign In'} — 111iridescence</title>
  <style>${CSS}</style>
</head>
<body>
  <div class="card">
    <h2>🔐 ${showReg ? 'Create Account' : 'Welcome back'}</h2>
    <p class="subtitle">${showReg ? 'Join 111iridescence' : 'Sign in to continue'}</p>

    ${statusMsg ? `<div class="msg ${isSuccess ? 'ok' : 'err'}">${statusMsg}</div>` : ''}

    <div id="loginSection" style="display:${showReg ? 'none' : 'block'}">
      <form method="POST" action="/auth/login" autocomplete="on">
        <input type="hidden" name="redirect" value="${redirect}">
        <label>Username</label>
        <input type="text" name="u" placeholder="your username" required autocomplete="username">
        <label>Password</label>
        <input type="password" name="p" placeholder="••••••••" required autocomplete="current-password">
        <button type="submit" class="btn btn-primary">Sign In</button>
      </form>
      <div class="divider">or</div>
      <button class="btn btn-secondary" onclick="toggle()">Create an account</button>
    </div>

    <div id="regSection" style="display:${showReg ? 'block' : 'none'}">
      <form method="POST" action="/auth/register" autocomplete="on">
        <input type="hidden" name="redirect" value="${redirect}">
        <label>Username</label>
        <input type="text" name="u" placeholder="choose a username" required autocomplete="username" minlength="3">
        <label>Password</label>
        <input type="password" name="p" placeholder="••••••••" required autocomplete="new-password" minlength="6">
        <button type="submit" class="btn btn-primary" style="background:var(--s);color:#000">Create Account</button>
      </form>
      <div class="divider">or</div>
      <button class="btn btn-secondary" onclick="toggle()">Already have an account?</button>
    </div>
  </div>

  <script>
    function toggle() {
      const l = document.getElementById('loginSection');
      const r = document.getElementById('regSection');
      const showing = l.style.display !== 'none';
      l.style.display = showing ? 'none' : 'block';
      r.style.display = showing ? 'block' : 'none';
      document.title = (showing ? 'Create Account' : 'Sign In') + ' — 111iridescence';
    }
  </script>
</body>
</html>`;
}
