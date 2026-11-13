// aerascps. scenepack site for Cloudflare Workers.
// Pages come from ./public (static assets). Data lives in a D1 database (binding: DB).
// Scenepack files are optional: they go to an R2 bucket if one is bound as FILES;
// without it, creators paste a link instead.

const CATS = ['music', 'tv', 'movies', 'series'];
const DISCORD = 'https://discord.com/api';
const SESSION_MS = 12 * 60 * 60 * 1000;
const PART_BYTES = 50 * 1024 * 1024; // each upload request stays under Cloudflare's 100 MB body limit

class Bad extends Error { constructor(code, msg) { super(msg); this.code = code; } }

// ---------- settings ----------
function config(env) {
  return {
    base: String(env.BASE_URL || '').replace(/\/$/, ''),
    clientId: String(env.DISCORD_CLIENT_ID || ''), clientSecret: String(env.DISCORD_CLIENT_SECRET || ''),
    guildId: String(env.DISCORD_GUILD_ID || ''), adminRoleId: String(env.ADMIN_ROLE_ID || ''), creatorRoleId: String(env.CREATOR_ROLE_ID || ''),
    adminUserIds: String(env.ADMIN_USER_IDS || '').split(',').map(s => s.trim()).filter(Boolean),
    webhook: String(env.REQUEST_WEBHOOK || ''),
    maxUpload: (Number(env.MAX_UPLOAD_MB) || 10240) * 1024 * 1024
  };
}

// ---------- data (one JSON document in D1) ----------
const blank = () => ({ settings: { announcement: { text: '', link: '' }, socials: { discord: '', instagram: '', tiktok: '' } }, packs: [], team: [], requests: [] });
function normalize(raw) {
  const d = Object.assign(blank(), raw || {});
  d.packs.forEach(p => { if (!CATS.includes(p.category)) p.category = 'music'; if (!p.subject) p.subject = 'Unknown'; });
  return d;
}
let tableReady = false;
async function loadDb(env) {
  if (!env.DB) throw new Bad(503, 'No database is connected. Add a D1 database to this Worker with the binding name DB (see README).');
  if (!tableReady) { await env.DB.prepare('CREATE TABLE IF NOT EXISTS store (k TEXT PRIMARY KEY, v TEXT NOT NULL)').run(); tableReady = true; }
  const row = await env.DB.prepare('SELECT v FROM store WHERE k = ?').bind('db').first();
  return normalize(row ? JSON.parse(row.v) : null);
}
const save = (env, db) => env.DB.prepare('INSERT INTO store (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind('db', JSON.stringify(db)).run();

// ---------- helpers ----------
const hex = n => [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, '0')).join('');
const id = () => hex(6);
const slug = s => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const str = (v, max, required) => {
  const s = String(v == null ? '' : v).trim().slice(0, max);
  if (required && !s) throw new Bad(400, 'A required field is empty.');
  return s;
};
const link = v => {
  const s = str(v, 500);
  if (s && !/^https:\/\/[^\s]+$/.test(s)) throw new Bad(400, 'Links must start with https://');
  return s;
};
const safeName = v => str(v, 120).replace(/[^\w.\- ()]/g, '_') || 'scenepack';
const SEC = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin', 'Cache-Control': 'no-store' };
const json = (body, code = 200) => new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json; charset=utf-8', ...SEC } });
function redirect(to, cookies = []) {
  const h = new Headers({ Location: to, 'Cache-Control': 'no-store' });
  cookies.forEach(c => h.append('Set-Cookie', c));
  return new Response(null, { status: 302, headers: h });
}
function cookies(request) {
  const o = {};
  (request.headers.get('cookie') || '').split(';').forEach(c => { const i = c.indexOf('='); if (i > 0) o[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim()); });
  return o;
}
const cookie = (cfg, name, val, maxAge) => `${name}=${encodeURIComponent(val)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${cfg.base.startsWith('https://') ? '; Secure' : ''}`;
async function readBody(request) {
  if (Number(request.headers.get('content-length')) > 20000) throw new Bad(413, 'Too much data.');
  const text = await request.text();
  if (text.length > 20000) throw new Bad(413, 'Too much data.');
  try { return text ? JSON.parse(text) : {}; } catch { throw new Bad(400, 'Invalid JSON.'); }
}

// ---------- sessions: a signed cookie, nothing stored on the server ----------
const enc = new TextEncoder();
const b64 = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
let keyCache = { secret: null, key: null };
async function hmacKey(cfg) {
  if (keyCache.secret !== cfg.clientSecret) keyCache = { secret: cfg.clientSecret, key: await crypto.subtle.importKey('raw', enc.encode('aerascps-session:' + cfg.clientSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']) };
  return keyCache.key;
}
const mac = async (cfg, payload) => b64(new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(cfg), enc.encode(payload))));
async function seal(cfg, obj) { const payload = b64(enc.encode(JSON.stringify(obj))); return payload + '.' + await mac(cfg, payload); }
async function unseal(cfg, token) {
  const [payload, sig] = String(token || '').split('.');
  if (!payload || !sig || !cfg.clientSecret) return null;
  const good = await mac(cfg, payload);
  if (good.length !== sig.length) return null;
  let diff = 0; for (let i = 0; i < good.length; i++) diff |= good.charCodeAt(i) ^ sig.charCodeAt(i);
  if (diff) return null;
  try { return JSON.parse(new TextDecoder().decode(unb64(payload))); } catch { return null; }
}
async function session(cfg, request) {
  const s = await unseal(cfg, cookies(request).sid);
  return s && s.user && s.exp > Date.now() ? s : null;
}
async function need(cfg, request, role) {
  const s = await session(cfg, request);
  if (!s) throw new Bad(401, 'Sign in with Discord first.');
  if (role === 'admin' && !s.admin) throw new Bad(403, 'Your Discord account does not have the admin role.');
  if (role === 'creator' && !(s.creator || s.admin)) throw new Bad(403, 'Your Discord account does not have the creator role.');
  return s;
}
const hits = new Map();
function limit(request) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const now = Date.now(), list = (hits.get(ip) || []).filter(t => now - t < 600000);
  if (list.length >= 5) throw new Bad(429, 'Too many requests. Try again in a few minutes.');
  list.push(now); hits.set(ip, list);
}
const publicPack = p => ({ id: p.id, title: p.title, category: p.category, subject: p.subject, quality: p.quality, badge: p.badge, link: p.link, file: p.file ? { name: p.file.name, size: p.file.size } : null, image: p.image, uploader: p.uploader, createdAt: p.createdAt });
async function dropFile(env, pk) {
  if (!pk || !env.FILES) return;
  try {
    if (pk.file && pk.file.key) await env.FILES.delete(pk.file.key);
    if (pk.pending) await env.FILES.resumeMultipartUpload(pk.pending.key, pk.pending.uploadId).abort();
  } catch (e) { console.error('Could not delete stored file:', e.message); }
}

// ---------- Discord sign-in ----------
async function discord(pathname, token) {
  const r = await fetch(DISCORD + pathname, { headers: { Authorization: 'Bearer ' + token } });
  return r.ok ? r.json() : null;
}
async function callback(cfg, request, url) {
  const c = cookies(request), state = url.searchParams.get('state') || '', code = url.searchParams.get('code');
  const [nonce, next] = state.split('.');
  if (!code || !nonce || c.st !== nonce) return redirect('/');
  const tr = await fetch(DISCORD + '/oauth2/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, grant_type: 'authorization_code', code, redirect_uri: cfg.base + '/auth/callback' })
  });
  if (!tr.ok) return redirect('/');
  const token = (await tr.json()).access_token;
  const user = await discord('/users/@me', token);
  if (!user) return redirect('/');
  const member = await discord(`/users/@me/guilds/${cfg.guildId}/member`, token); // null if not in the server
  const roles = member ? member.roles : [];
  const sid = await seal(cfg, {
    user: { id: user.id, username: user.global_name || user.username, avatar: user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=64` : '' },
    admin: roles.includes(cfg.adminRoleId) || cfg.adminUserIds.includes(user.id), creator: roles.includes(cfg.creatorRoleId), exp: Date.now() + SESSION_MS
  });
  return redirect('/#' + (['admin', 'studio'].includes(next) ? next : 'home'), [cookie(cfg, 'sid', sid, SESSION_MS / 1000), cookie(cfg, 'st', '', 0)]);
}

// ---------- routes ----------
async function handle(request, env, ctx) {
  const url = new URL(request.url), p = url.pathname, m = request.method, cfg = config(env);
  let k;

  if (m !== 'GET' && m !== 'HEAD') {
    // only accept changes sent from this site itself
    const origin = request.headers.get('origin');
    if (origin && origin !== cfg.base) {
      let oh = ''; try { oh = new URL(origin).host; } catch { /* not a URL */ }
      if (oh !== url.host) throw new Bad(403, `This page was opened at ${origin}, which is not this site's address. Set BASE_URL to ${origin}.`);
    }
    const part = m === 'PUT' && /^\/api\/studio\/packs\/\w+\/upload\/part$/.test(p);
    if (!part && !String(request.headers.get('content-type') || '').startsWith('application/json')) throw new Bad(415, 'JSON only.');
  }

  // auth
  if (p.startsWith('/auth/') && (!cfg.base || !cfg.clientId || !cfg.clientSecret)) throw new Bad(500, 'Discord sign-in is not set up yet: BASE_URL, DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET are needed (see README).');
  if (p === '/auth/login') {
    const nonce = hex(16), next = ['admin', 'studio'].includes(url.searchParams.get('next')) ? url.searchParams.get('next') : 'home';
    const q = new URLSearchParams({ client_id: cfg.clientId, response_type: 'code', redirect_uri: cfg.base + '/auth/callback', scope: 'identify guilds.members.read', state: nonce + '.' + next, prompt: 'none' });
    return redirect('https://discord.com/oauth2/authorize?' + q, [cookie(cfg, 'st', nonce, 600)]);
  }
  if (p === '/auth/callback') return callback(cfg, request, url);
  if (p === '/auth/logout') return redirect('/', [cookie(cfg, 'sid', '', 0)]);

  if (p === '/api/me' && m === 'GET') { const s = await session(cfg, request); return json(s ? { user: s.user, admin: s.admin, creator: s.creator || s.admin } : { user: null, admin: false, creator: false }); }

  if (!p.startsWith('/api/') && !p.startsWith('/download/')) {
    if (env.ASSETS && (m === 'GET' || m === 'HEAD')) return env.ASSETS.fetch(request);
    throw new Bad(404, 'Not found.');
  }

  const db = await loadDb(env);
  const ownPack = (s, pid) => db.packs.find(x => x.id === pid && (s.admin || (x.uploaderId === s.user.id && x.status !== 'approved')));

  // public
  if (p === '/api/site' && m === 'GET') return json({ settings: db.settings, uploads: env.FILES ? 'r2' : 'none', maxUploadMB: Math.round(cfg.maxUpload / 1048576), packs: db.packs.filter(x => x.status === 'approved').map(publicPack), team: db.team });
  if (p === '/api/requests' && m === 'POST') {
    limit(request);
    const b = await readBody(request);
    const r = { id: id(), artist: str(b.artist, 80, true), scene: str(b.scene, 200, true), quality: str(b.quality, 20), notes: str(b.notes, 1000), user: str(b.user, 60, true), createdAt: Date.now() };
    db.requests.unshift(r); db.requests = db.requests.slice(0, 200); await save(env, db);
    if (cfg.webhook) {
      const send = fetch(cfg.webhook, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ allowed_mentions: { parse: [] }, content: `**Scenepack request**\nName: ${r.artist}\nScene: ${r.scene}\nQuality: ${r.quality || 'Any'}\nDetails: ${r.notes || 'none'}\nRequested by: ${r.user}`.slice(0, 1900) }) }).catch(() => {});
      if (ctx && ctx.waitUntil) ctx.waitUntil(send);
    }
    return json({ ok: true, forwarded: !!cfg.webhook });
  }

  // scenepack studio (creators)
  if (p === '/api/studio/packs' && m === 'GET') { const s = await need(cfg, request, 'creator'); return json({ packs: db.packs.filter(x => x.uploaderId === s.user.id) }); }
  if (p === '/api/studio/packs' && m === 'POST') {
    const s = await need(cfg, request, 'creator'), b = await readBody(request);
    const category = CATS.includes(b.category) ? b.category : 'music';
    let subject = str(b.subject, 60, true);
    if (!slug(subject)) throw new Bad(400, 'Use letters or numbers in the name.');
    const same = db.packs.find(x => x.category === category && slug(x.subject) === slug(subject));
    if (same) subject = same.subject; // keep one spelling per name
    const badge = ['Ready', 'In progress', 'To be updated'].includes(b.badge) ? b.badge : 'Ready';
    const quality = ['4K', '1080p', '720p'].includes(b.quality) ? b.quality : '1080p';
    const pid = id();
    db.packs.unshift({ id: pid, title: str(b.title, 80, true), category, subject, quality, badge, link: link(b.link), image: link(b.image), uploader: s.user.username, uploaderId: s.user.id, status: 'pending', createdAt: Date.now() });
    await save(env, db); return json({ ok: true, id: pid });
  }
  if ((k = p.match(/^\/api\/studio\/packs\/(\w+)$/)) && m === 'DELETE') {
    const s = await need(cfg, request, 'creator'), i = db.packs.findIndex(x => x.id === k[1] && x.uploaderId === s.user.id && x.status !== 'approved');
    if (i < 0) throw new Bad(404, 'Only your own unapproved scenepacks can be deleted here.');
    await dropFile(env, db.packs[i]); db.packs.splice(i, 1); await save(env, db); return json({ ok: true });
  }

  // file upload to R2, sent in parts
  if ((k = p.match(/^\/api\/studio\/packs\/(\w+)\/upload\/(start|part|complete)$/))) {
    if (!env.FILES) throw new Bad(400, 'File storage is not set up, so add a link to the scenepack instead.');
    const s = await need(cfg, request, 'creator'), pk = ownPack(s, k[1]);
    if (!pk) throw new Bad(404, 'Scenepack not found.');
    if (k[2] === 'start' && m === 'POST') {
      const b = await readBody(request);
      if (Number(b.size) > cfg.maxUpload) throw new Bad(413, `File is larger than ${+(cfg.maxUpload / 1073741824).toFixed(1)} GB.`);
      await dropFile(env, pk); delete pk.file;
      const name = safeName(b.name), up = await env.FILES.createMultipartUpload(`packs/${pk.id}/${name}`);
      pk.pending = { key: up.key, uploadId: up.uploadId, name };
      await save(env, db); return json({ uploadId: up.uploadId, partBytes: PART_BYTES });
    }
    if (!pk.pending || (k[2] === 'part' && pk.pending.uploadId !== url.searchParams.get('uploadId'))) throw new Bad(400, 'This upload is no longer active. Start it again.');
    const up = env.FILES.resumeMultipartUpload(pk.pending.key, pk.pending.uploadId);
    if (k[2] === 'part' && m === 'PUT') {
      const n = Number(url.searchParams.get('n'));
      if (!Number.isInteger(n) || n < 1 || n > Math.ceil(cfg.maxUpload / PART_BYTES)) throw new Bad(413, 'File is too large.');
      if (Number(request.headers.get('content-length')) > PART_BYTES + 1024) throw new Bad(413, 'Part is too large.');
      const done = await up.uploadPart(n, request.body);
      return json({ partNumber: done.partNumber, etag: done.etag });
    }
    if (k[2] === 'complete' && m === 'POST') {
      const b = await readBody(request);
      const parts = (Array.isArray(b.parts) ? b.parts : []).map(x => ({ partNumber: Number(x.partNumber), etag: String(x.etag) }));
      const obj = await up.complete(parts);
      pk.file = { name: pk.pending.name, size: (obj && obj.size) || Math.max(0, Number(b.size) || 0), key: pk.pending.key };
      delete pk.pending; await save(env, db); return json({ ok: true });
    }
    throw new Bad(404, 'Not found.');
  }

  // download: public once approved; the uploader and admins can fetch it earlier
  if ((k = p.match(/^\/download\/(\w+)$/)) && m === 'GET') {
    const pk = db.packs.find(x => x.id === k[1]), s = await session(cfg, request);
    if (!pk || !pk.file || !pk.file.key || !env.FILES || !(pk.status === 'approved' || (s && (s.admin || s.user.id === pk.uploaderId)))) throw new Bad(404, 'File not found.');
    const wantsRange = request.headers.has('range');
    let obj;
    try { obj = await env.FILES.get(pk.file.key, wantsRange ? { range: request.headers } : undefined); }
    catch { obj = await env.FILES.get(pk.file.key); }
    if (!obj) throw new Bad(404, 'File not found.');
    const h = new Headers({ 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${pk.file.name}"`, 'Accept-Ranges': 'bytes', 'X-Content-Type-Options': 'nosniff' });
    if (obj.httpEtag) h.set('ETag', obj.httpEtag);
    let status = 200;
    if (wantsRange && obj.range && obj.size) {
      const off = obj.range.offset != null ? obj.range.offset : obj.size - (obj.range.suffix || 0);
      const len = obj.range.length != null ? obj.range.length : obj.size - off;
      if (off > 0 || len < obj.size) { h.set('Content-Range', `bytes ${off}-${off + len - 1}/${obj.size}`); status = 206; }
    }
    return new Response(obj.body, { status, headers: h });
  }

  // control room (admins)
  if (p.startsWith('/api/admin/')) {
    await need(cfg, request, 'admin');
    if (p === '/api/admin/data' && m === 'GET') return json({ packs: db.packs, requests: db.requests });
    if ((k = p.match(/^\/api\/admin\/packs\/(\w+)\/(approve|reject)$/)) && m === 'POST') {
      const pk = db.packs.find(x => x.id === k[1]); if (!pk) throw new Bad(404, 'Scenepack not found.');
      pk.status = k[2] === 'approve' ? 'approved' : 'rejected'; await save(env, db); return json({ ok: true });
    }
    if ((k = p.match(/^\/api\/admin\/(packs|team|requests)\/(\w+)$/)) && m === 'DELETE') {
      if (k[1] === 'packs') await dropFile(env, db.packs.find(x => x.id === k[2]));
      db[k[1]] = db[k[1]].filter(x => x.id !== k[2]); await save(env, db); return json({ ok: true });
    }
    if (p === '/api/admin/team' && m === 'POST') {
      const b = await readBody(request);
      db.team.push({ id: id(), name: str(b.name, 60, true), role: str(b.role, 60, true), discord: link(b.discord) }); await save(env, db); return json({ ok: true });
    }
    if (p === '/api/admin/settings' && m === 'PUT') {
      const b = await readBody(request);
      db.settings = { announcement: { text: str(b.text, 160), link: link(b.link) }, socials: { discord: link(b.discord), instagram: link(b.instagram), tiktok: link(b.tiktok) } };
      await save(env, db); return json({ ok: true });
    }
  }
  throw new Bad(404, 'Not found.');
}

export default {
  async fetch(request, env, ctx) {
    try { return await handle(request, env, ctx); }
    catch (e) {
      if (!(e instanceof Bad)) console.error(e);
      return json({ error: e instanceof Bad ? e.message : 'Server error: ' + (e && e.message ? e.message : 'unknown') }, e.code || 500);
    }
  }
};
