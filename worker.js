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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
:root{--bg:#0f1117;--card:#161b22;--txt-main:#f8fafc;--txt-muted:#94a3b8;--p:#6366f1;--p-hover:#4f46e5;--s:#0ea5e9;--err:#f43f5e;--good:#10b981;--border:rgba(255,255,255,0.08);--ring:rgba(99,102,241,0.5)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--txt-main);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;line-height:1.5}
.card{background:var(--card);padding:40px 32px;border-radius:24px;border:1px solid var(--border);width:100%;max-width:380px;box-shadow:0 24px 48px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.02) inset}
h2{text-align:center;margin-bottom:8px;font-size:1.6em;font-weight:700;letter-spacing:-0.02em}
.subtitle{text-align:center;color:var(--txt-muted);font-size:0.95em;margin-bottom:32px}
label{display:block;font-size:0.85em;color:var(--txt-muted);margin-bottom:6px;margin-top:16px;font-weight:500}
input{background:rgba(0,0,0,0.2);border:1px solid var(--border);color:var(--txt-main);padding:12px 16px;border-radius:12px;width:100%;font-size:1em;transition:all 0.2s;font-family:inherit}
input:focus{outline:none;border-color:var(--p);box-shadow:0 0 0 3px var(--ring)}
.btn{cursor:pointer;border:none;padding:12px;border-radius:12px;width:100%;font-weight:600;font-size:1em;transition:all 0.2s;margin-top:24px;font-family:inherit;display:inline-flex;align-items:center;justify-content:center}
.btn-primary{background:var(--p);color:#fff;box-shadow:0 4px 12px rgba(99,102,241,0.2)}
.btn-primary:hover{background:var(--p-hover);transform:translateY(-1px);box-shadow:0 6px 16px rgba(99,102,241,0.3)}
.btn-secondary{background:rgba(255,255,255,0.05);color:var(--txt-muted);border:1px solid var(--border);margin-top:12px;box-shadow:none}
.btn-secondary:hover{background:rgba(255,255,255,0.1);color:var(--txt-main)}
.msg{text-align:center;font-size:0.9em;padding:10px;border-radius:8px;margin-top:16px;font-weight:500}
.msg.err{color:var(--err);background:rgba(244,63,94,0.1);border:1px solid rgba(244,63,94,0.2)}
.msg.ok{color:var(--good);background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.2)}
.divider{text-align:center;color:var(--txt-muted);font-size:0.85em;margin:24px 0;position:relative;display:flex;align-items:center}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
.divider::before{margin-right:12px}.divider::after{margin-left:12px}
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
        <button type="submit" class="btn btn-primary" style="background:var(--s);color:#fff">Create Account</button>
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
