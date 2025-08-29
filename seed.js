// seed.js
require('dotenv').config();
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const DB_PATH = process.env.DB_PATH || './data.db';
const db = new Database(DB_PATH);

// create admin if not exists
const username = 'admin';
const password = 'admin123'; // change immediately after login
const h = bcrypt.hashSync(password, 10);

const exists = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
if (!exists) {
  db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run(username, h);
  console.log('Admin created:', username, password);
} else {
  console.log('Admin exists:', username);
}

// set default settings if missing
function createIfNotExists(k, v) {
  const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(k);
  if (!r) db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run(k, v);
}
createIfNotExists('CF_API_TOKEN', process.env.CF_API_TOKEN || '');
createIfNotExists('CF_ZONE_ID', process.env.CF_ZONE_ID || '');
createIfNotExists('TURNSTILE_SITEKEY', '');
createIfNotExists('TURNSTILE_SECRET', '');
createIfNotExists('ADSTERRA_PUBLISHER_API_KEY', '');
createIfNotExists('ADSTERRA_DOMAIN_ID', '');
createIfNotExists('ADSTERRA_SCRIPT', '<!-- paste Adsterra script here -->');
createIfNotExists('DAILY_CREATE_LIMIT', '3');
createIfNotExists('BLOCK_VPN', 'false');
createIfNotExists('IPINFO_TOKEN', process.env.IPINFO_TOKEN || '');
createIfNotExists('reserved_list', JSON.stringify(['www','mail','ftp','admin','api','ns1','ns2']));

console.log('Seeding done. Please change default admin password.');
