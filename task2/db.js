// Thin SQLite wrapper. Opens (and lazily seeds) shop.db.
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DB_PATH = path.join(__dirname, 'shop.db');

function applySqlFile(db, file) {
  db.exec(fs.readFileSync(path.join(__dirname, file), 'utf8'));
}

function open() {
  const freshNeeded = !fs.existsSync(DB_PATH);
  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  if (freshNeeded) {
    applySqlFile(db, 'schema.sql');
    applySqlFile(db, 'seed-data.sql');
  }
  return db;
}

module.exports = { open, DB_PATH, applySqlFile };
