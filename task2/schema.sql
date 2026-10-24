-- ShopSmart schema (SQLite)
-- Used by seed.js / seed-data.sql to build a realistic e-commerce database.

DROP TABLE IF EXISTS reviews;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT    NOT NULL UNIQUE,
  email         TEXT    NOT NULL,
  -- SHA-256 hex of the password. Stored as a hash so the UNION-based SQLi
  -- demo can "dump password hashes" like a real breach.
  password_hash TEXT    NOT NULL,
  is_admin      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE products (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL,
  description TEXT    NOT NULL,
  price       REAL    NOT NULL,
  stock       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE reviews (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL REFERENCES products(id),
  author     TEXT    NOT NULL,
  body       TEXT    NOT NULL,     -- rendered unescaped in VULN mode -> stored XSS
  rating     INTEGER NOT NULL DEFAULT 5,
  created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
