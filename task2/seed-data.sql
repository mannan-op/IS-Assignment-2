-- ShopSmart seed data (SQLite).
-- Run against a database already created with schema.sql, e.g.:
--   sqlite3 shop.db ".read schema.sql" ".read seed-data.sql"
-- or just run:  npm run seed   (seed.js applies both files).
--
-- password_hash is SHA-256(hex) of the plaintext noted in the comment.

INSERT INTO users (username, email, password_hash, is_admin) VALUES
  ('admin', 'admin@shopsmart.test', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', 1), -- admin123
  ('alice', 'alice@example.com',    '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e', 0), -- password1
  ('bob',   'bob@example.com',      'f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7', 0), -- hunter2
  ('carol', 'carol@example.com',    '1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032', 0), -- letmein
  ('dave',  'dave@example.com',     '65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5', 0); -- qwerty

INSERT INTO products (name, description, price, stock) VALUES
  ('Mechanical Keyboard',  'Hot-swappable 75% mechanical keyboard with PBT keycaps.', 119.99, 42),
  ('Wireless Mouse',       'Lightweight 2.4GHz + Bluetooth mouse, 70h battery.',        39.99, 130),
  ('27-inch Monitor',      '27" 1440p 165Hz IPS display with USB-C.',                  289.00, 18),
  ('USB-C Hub',            '7-in-1 hub: HDMI, 3x USB-A, SD, microSD, 100W PD.',         49.50, 75),
  ('Noise-Cancelling Headphones', 'Over-ear ANC headphones, 30h battery.',            199.00, 23),
  ('Webcam 1080p',         '1080p60 webcam with dual mics and privacy shutter.',        59.99, 60),
  ('Laptop Stand',         'Aluminium adjustable laptop stand.',                        34.95, 88),
  ('Desk Mat',             'Large stitched-edge desk mat, 900x400mm.',                  19.99, 200);

INSERT INTO reviews (product_id, author, body, rating) VALUES
  (1, 'alice', 'Best keyboard I have owned. Thocky and clean.', 5),
  (1, 'bob',   'Great typing feel, a bit loud for the office.',  4),
  (2, 'carol', 'Super light and the battery really does last.',  5),
  (3, 'dave',  'Colours are gorgeous, stand wobbles slightly.',  4),
  (5, 'alice', 'ANC is excellent on flights.',                   5);
