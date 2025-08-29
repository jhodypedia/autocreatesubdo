// server.js
require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch'); // v2
const Database = require('better-sqlite3');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const {
  PORT = 4000,
  DOMAIN,
  DB_PATH = './data.db',
  SESSION_SECRET = 'change_this'
} = process.env;

if (!DOMAIN) {
  console.error('Please set DOMAIN in .env');
  process.exit(1);
}

// DB init
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// create tables
db.prepare(`CREATE TABLE IF NOT EXISTS subdomains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE,
  owner TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  cf_record_id TEXT,
  target TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS creation_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
)`).run();

// reserved list load from settings or default
let reserved = ['www','mail','ftp','admin','api','ns1','ns2'];
try {
  const r = db.prepare("SELECT value FROM settings WHERE key = 'reserved_list'").get();
  if (r && r.value) {
    const parsed = JSON.parse(r.value);
    if (Array.isArray(parsed)) reserved = parsed;
  }
} catch(e){ console.error('reserved load err', e); }

// express
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// trust proxy if behind proxy like Cloudflare
app.set('trust proxy', true);

// session
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set true if HTTPS
}));

// flash helper
app.use((req,res,next) => {
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

// helpers
function sanitizeName(name) {
  return (''+name).toLowerCase()
    .replace(/[^a-z0-9-]/g,'')
    .replace(/^-+|-+$/g,'')
    .slice(0,63);
}
function isValidIPv4(ip) {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  return ip.split('.').every(o => { const n = Number(o); return n >=0 && n <=255; });
}
function isValidHostname(h) {
  return /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(h);
}
function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}
function setSetting(key, value) {
  db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, value);
}
function isReserved(name) {
  return reserved.includes(name);
}
async function isVPNorHosting(ip) {
  const token = getSetting('IPINFO_TOKEN') || process.env.IPINFO_TOKEN || '';
  if (!token) return false;
  try {
    const res = await fetch(`https://ipinfo.io/${ip}/json?token=${token}`);
    const j = await res.json();
    const org = (j.org || '').toLowerCase();
    if (/vpn|hosting|digitalocean|ovh|amazon|aws|gcp|google|microsoft|azure|linode|hetzner|vps|cloudflare/i.test(org)) return true;
  } catch(e) {
    console.error('ipinfo error', e);
  }
  return false;
}

// Cloudflare record handlers (reads CF_API_TOKEN & CF_ZONE_ID from settings or env)
async function createCloudflareRecord(name, target) {
  const cfToken = getSetting('CF_API_TOKEN') || process.env.CF_API_TOKEN;
  const cfZone = getSetting('CF_ZONE_ID') || process.env.CF_ZONE_ID;
  if (!cfToken || !cfZone) throw new Error('Cloudflare API token/zone not configured');

  const fqdn = `${name}.${DOMAIN}`;
  let type = isValidIPv4(target) ? 'A' : (isValidHostname(target) ? 'CNAME' : null);
  if (!type) throw new Error('Invalid target');

  const body = { type, name: fqdn, content: target, ttl: 120, proxied: false };
  const r = await fetch(`https://api.cloudflare.com/client/v4/zones/${cfZone}/dns_records`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const j = await r.json();
  if (!j.success) throw new Error(JSON.stringify(j.errors || j));
  return j.result;
}
async function deleteCloudflareRecord(recordId) {
  const cfToken = getSetting('CF_API_TOKEN') || process.env.CF_API_TOKEN;
  const cfZone = getSetting('CF_ZONE_ID') || process.env.CF_ZONE_ID;
  if (!cfToken || !cfZone) throw new Error('Cloudflare API token/zone not configured');
  const r = await fetch(`https://api.cloudflare.com/client/v4/zones/${cfZone}/dns_records/${recordId}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' }
  });
  return r.json();
}

// Turnstile verification
async function verifyTurnstile(token, ip) {
  const secret = getSetting('TURNSTILE_SECRET') || '';
  if (!secret) return { success: true }; // if not configured, allow (dev)
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `secret=${encodeURIComponent(secret)}&response=${encodeURIComponent(token)}&remoteip=${encodeURIComponent(ip)}`
  });
  return res.json();
}

// Adsterra Publisher API fetch (publisher stats)
async function fetchAdsterraStats(domainId, startDate, endDate) {
  const apiKey = getSetting('ADSTERRA_PUBLISHER_API_KEY') || '';
  if (!apiKey || !domainId) return null;
  const url = `https://api3.adsterratools.com/publisher/stats.json?domain=${domainId}&start_date=${startDate}&finish_date=${endDate}&group_by=date`;
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json', 'X-API-Key': apiKey }
    });
    if (!res.ok) throw new Error('Adsterra API error ' + res.status);
    return res.json();
  } catch(e) {
    console.error('adsterra fetch error', e);
    return null;
  }
}

// admin auth middleware
function requireAdmin(req, res, next) {
  if (req.session && req.session.adminId) return next();
  req.session.flash = { type: 'danger', msg: 'Login required' };
  return res.redirect('/admin/login');
}

// Routes

// Home - create form
app.get('/', (req, res) => {
  const turnstileSite = getSetting('TURNSTILE_SITEKEY') || '';
  const adScript = getSetting('ADSTERRA_SCRIPT') || '';
  res.render('index', { domain: DOMAIN, turnstileSite, adScript });
});

// Create subdomain (form submit). Accept both form submit and AJAX (JSON)
app.post('/create', async (req, res) => {
  try {
    const nameRaw = req.body.name || '';
    const target = (req.body.target || '').trim();
    const token = req.body['cf-turnstile-response'] || req.body.turnstileToken || '';
    const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

    const name = sanitizeName(nameRaw);
    // verify turnstile
    const vt = await verifyTurnstile(token, clientIp);
    if (!vt || !vt.success) {
      const msg = 'Captcha verification failed';
      if (req.headers.accept && req.headers.accept.indexOf('application/json')>=0) return res.json({ success:false, message:msg });
      req.session.flash = { type:'danger', msg }; return res.redirect('/');
    }

    if (!name || !target) {
      const msg = 'Name & target required';
      if (req.headers.accept && req.headers.accept.indexOf('application/json')>=0) return res.json({ success:false, message:msg });
      req.session.flash = { type:'danger', msg }; return res.redirect('/');
    }

    if (isReserved(name)) {
      const msg = 'Reserved name';
      if (req.headers.accept && req.headers.accept.indexOf('application/json')>=0) return res.json({ success:false, message:msg });
      req.session.flash = { type:'danger', msg }; return res.redirect('/');
    }

    if (!(isValidIPv4(target) || isValidHostname(target))) {
      const msg = 'Invalid target - must be IPv4 or hostname';
      if (req.headers.accept && req.headers.accept.indexOf('application/json')>=0) return res.json({ success:false, message:msg });
      req.session.flash = { type:'danger', msg }; return res.redirect('/');
    }

    const blockVpn = (getSetting('BLOCK_VPN') === 'true');
    if (blockVpn && await isVPNorHosting(clientIp)) {
      const msg = 'VPN/hosting detected - blocked';
      if (req.headers.accept && req.headers.accept.indexOf('application/json')>=0) return res.json({ success:false, message:msg });
      req.session.flash = { type:'danger', msg }; return res.redirect('/');
    }

    // daily limit
    const limitVal = Number(getSetting('DAILY_CREATE_LIMIT') || 3);
    const since = new Date(); since.setHours(0,0,0,0);
    const row = db.prepare('SELECT COUNT(*) as cnt FROM creation_log WHERE owner = ? AND created_at >= ?').get(clientIp, since.toISOString());
    if (row && row.cnt >= limitVal) {
      const msg = `Daily limit reached (${limitVal})`;
      if (req.headers.accept && req.headers.accept.indexOf('application/json')>=0) return res.json({ success:false, message:msg });
      req.session.flash = { type:'danger', msg }; return res.redirect('/');
    }

    // uniqueness
    const exists = db.prepare('SELECT * FROM subdomains WHERE name = ?').get(name);
    if (exists) {
      const msg = 'Subdomain already exists';
      if (req.headers.accept && req.headers.accept.indexOf('application/json')>=0) return res.json({ success:false, message:msg });
      req.session.flash = { type:'danger', msg }; return res.redirect('/');
    }

    // create record
    const cf = await createCloudflareRecord(name, target);

    // save
    db.prepare('INSERT INTO subdomains (name, owner, cf_record_id, target) VALUES (?,?,?,?)').run(name, clientIp, cf.id, target);
    db.prepare('INSERT INTO creation_log (owner) VALUES (?)').run(clientIp);

    const msg = `Created ${name}.${DOMAIN} → ${target}`;
    if (req.headers.accept && req.headers.accept.indexOf('application/json')>=0) return res.json({ success:true, message:msg });
    req.session.flash = { type:'success', msg }; return res.redirect('/');
  } catch(err) {
    console.error(err);
    const msg = 'Error: ' + (err.message || String(err));
    if (req.headers.accept && req.headers.accept.indexOf('application/json')>=0) return res.json({ success:false, message:msg });
    req.session.flash = { type:'danger', msg }; return res.redirect('/');
  }
});

// public list
app.get('/list', (req, res) => {
  const subs = db.prepare('SELECT name, owner, target, created_at FROM subdomains ORDER BY created_at DESC LIMIT 200').all();
  const adScript = getSetting('ADSTERRA_SCRIPT') || '';
  res.render('list', { domain: DOMAIN, subs, adScript });
});

// admin login
app.get('/admin/login', (req, res) => {
  res.render('admin_login', { message: res.locals.flash ? res.locals.flash.msg : null });
});
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
  if (!admin) {
    req.session.flash = { type:'danger', msg:'Invalid credentials' }; return res.redirect('/admin/login');
  }
  if (!bcrypt.compareSync(password, admin.password_hash)) {
    req.session.flash = { type:'danger', msg:'Invalid credentials' }; return res.redirect('/admin/login');
  }
  req.session.adminId = admin.id;
  req.session.adminUser = admin.username;
  res.redirect('/admin');
});
app.get('/admin/logout', (req,res) => { req.session.destroy(()=>res.redirect('/admin/login')); });

// admin panel
app.get('/admin', requireAdmin, async (req,res) => {
  const subs = db.prepare('SELECT * FROM subdomains ORDER BY created_at DESC').all();
  const totalSubs = db.prepare('SELECT COUNT(*) as cnt FROM subdomains').get().cnt;
  const settingsRows = db.prepare('SELECT key, value FROM settings').all();
  const settingsObj = {};
  settingsRows.forEach(r => settingsObj[r.key] = r.value);

  // adsterra stats from Publisher API if configured
  const adDomainId = settingsObj['ADSTERRA_DOMAIN_ID'] || '';
  let adStats = null;
  if (adDomainId) {
    const today = new Date();
    const end = today.toISOString().slice(0,10);
    const startDateObj = new Date(); startDateObj.setDate(today.getDate() - 29);
    const start = startDateObj.toISOString().slice(0,10);
    adStats = await fetchAdsterraStats(adDomainId, start, end);
  }

  res.render('admin', {
    domain: DOMAIN,
    subs,
    totalSubs,
    reserved,
    settings: settingsObj,
    adStats,
    adminUser: req.session.adminUser
  });
});

// admin actions
app.post('/admin/reserve', requireAdmin, (req,res) => {
  const newName = sanitizeName(req.body.name || '');
  if (!newName) { req.session.flash = { type:'danger', msg:'Invalid name' }; return res.redirect('/admin'); }
  if (!reserved.includes(newName)) reserved.push(newName);
  setSetting('reserved_list', JSON.stringify(reserved));
  req.session.flash = { type:'success', msg:'Reserved added' };
  res.redirect('/admin');
});

app.post('/admin/delete/:name', requireAdmin, async (req,res) => {
  const name = sanitizeName(req.params.name);
  const row = db.prepare('SELECT * FROM subdomains WHERE name = ?').get(name);
  if (row) {
    try { await deleteCloudflareRecord(row.cf_record_id); } catch(e){ console.error('CF delete failed', e); }
    db.prepare('DELETE FROM subdomains WHERE name = ?').run(name);
  }
  req.session.flash = { type:'success', msg:'Subdomain deleted' };
  res.redirect('/admin');
});

app.post('/admin/settings', requireAdmin, (req,res) => {
  const keys = ['CF_API_TOKEN','CF_ZONE_ID','TURNSTILE_SITEKEY','TURNSTILE_SECRET','ADSTERRA_PUBLISHER_API_KEY','ADSTERRA_PUBLISHER_API_KEY','ADSTERRA_DOMAIN_ID','ADSTERRA_SCRIPT','DAILY_CREATE_LIMIT','BLOCK_VPN','IPINFO_TOKEN'];
  // store values from posted form
  Object.keys(req.body).forEach(k => {
    // only allow known keys
    if (['CF_API_TOKEN','CF_ZONE_ID','TURNSTILE_SITEKEY','TURNSTILE_SECRET','ADSTERRA_PUBLISHER_API_KEY','ADSTERRA_DOMAIN_ID','ADSTERRA_SCRIPT','DAILY_CREATE_LIMIT','BLOCK_VPN','IPINFO_TOKEN'].includes(k)) {
      setSetting(k, (req.body[k] || '').toString());
    }
  });
  req.session.flash = { type:'success', msg:'Settings saved' };
  res.redirect('/admin');
});

// export CSV
app.get('/admin/export/csv', requireAdmin, (req,res) => {
  const rows = db.prepare('SELECT name, target, owner, created_at FROM subdomains ORDER BY created_at').all();
  const header = 'name,target,owner,created_at\n';
  const csv = rows.map(r => `${r.name},${r.target},${r.owner},${r.created_at}`).join('\n');
  res.setHeader('Content-disposition', 'attachment; filename=subdomains.csv');
  res.set('Content-Type', 'text/csv');
  res.send(header + csv);
});

// health
app.get('/health', (req,res) => res.json({ ok:true }));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
