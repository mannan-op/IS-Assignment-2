// Rebuild shop.db from scratch: drop + schema.sql + seed-data.sql.
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { applySqlFile } = require('./db');

const DB_PATH = path.join(__dirname, 'shop.db');
for (const f of [DB_PATH, DB_PATH + '-wal', DB_PATH + '-shm']) {
  if (fs.existsSync(f)) fs.unlinkSync(f);
}
const db = new Database(DB_PATH);
applySqlFile(db, 'schema.sql');
applySqlFile(db, 'seed-data.sql');
const u = db.prepare('SELECT COUNT(*) c FROM users').get().c;
const p = db.prepare('SELECT COUNT(*) c FROM products').get().c;
const r = db.prepare('SELECT COUNT(*) c FROM reviews').get().c;
console.log(`Seeded shop.db -> users=${u} products=${p} reviews=${r}`);
db.close();
