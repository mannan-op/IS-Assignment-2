// ShopSmart — Information Security practical, Part 2.
// A single Express app that toggles between a VULNERABLE and a SAFE build
// via the VULN env var (see config.js). The SAME routes behave differently
// depending on config.VULN, so you can diff the two builds line-by-line.

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const { open } = require('./db');
const config = require('./config');

const db = open();
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Sessions / cookies
// SAFE build: SameSite=Strict (blocks cross-site cookie sending -> CSRF harder).
// VULN build: SameSite not set + session cookie happily rides along on
//             attacker-triggered POSTs.
// ---------------------------------------------------------------------------
app.use(session({
  name: 'sid',
  secret: 'shopsmart-demo-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: config.VULN ? false : 'strict',
    secure: false, // demo runs on http://localhost
  },
}));

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// Expose common values to every template.
app.use((req, res, next) => {
  res.locals.mode = config.MODE;
  res.locals.vuln = config.VULN;
  res.locals.user = req.session.user || null;
  // CSRF token only exists in SAFE mode.
  if (!config.VULN) {
    if (!req.session.csrf) req.session.csrf = crypto.randomBytes(16).toString('hex');
    res.locals.csrf = req.session.csrf;
  } else {
    res.locals.csrf = '';
  }
  next();
});

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

// SAFE-mode CSRF guard for state-changing POSTs.
function csrfGuard(req, res, next) {
  if (config.VULN) return next(); // intentionally unprotected
  const sent = req.body._csrf || req.headers['x-csrf-token'];
  if (!sent || sent !== req.session.csrf) {
    return res.status(403).render('message', {
      title: 'Blocked', heading: 'CSRF token invalid',
      text: 'This request was rejected because it did not carry a valid CSRF token (SAFE mode).',
    });
  }
  next();
}

// ---------------------------------------------------------------------------
// Home / product list
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY id').all();
  res.render('index', { products });
});

// ---------------------------------------------------------------------------
// SEARCH  -> Reflected XSS  +  UNION-based SQL injection (advanced)
// ---------------------------------------------------------------------------
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  let products = [];
  let sqlShown = '';
  let error = '';
  if (q) {
    if (config.VULN) {
      // VULNERABLE: raw string interpolation into the query.
      const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${q}%'`;
      sqlShown = sql;
      try {
        products = db.prepare(sql).all();
      } catch (e) {
        error = e.message;
      }
    } else {
      // SAFE: parameterised LIKE. No way to break out of the string literal.
      const sql = `SELECT id, name, price FROM products WHERE name LIKE ?`;
      sqlShown = sql + "   [param: %" + q + "%]";
      products = db.prepare(sql).all(`%${q}%`);
    }
  }
  res.render('search', { q, products, sqlShown, error });
});

// ---------------------------------------------------------------------------
// Blind boolean-based SQLi (intermediate) — a username lookup endpoint.
// Returns a simple exists/not-found with no echoing of data.
// ---------------------------------------------------------------------------
app.get('/api/user-exists', (req, res) => {
  const u = req.query.u || '';
  if (config.VULN) {
    const sql = `SELECT id FROM users WHERE username = '${u}'`;
    try {
      const row = db.prepare(sql).get();
      return res.json({ exists: !!row });
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
  }
  const row = db.prepare('SELECT id FROM users WHERE username = ?').get(u);
  res.json({ exists: !!row });
});

// ---------------------------------------------------------------------------
// AUTH — login (easy SQLi login bypass), register, logout
// ---------------------------------------------------------------------------
app.get('/login', (req, res) => res.render('login', { error: null, sqlShown: '' }));

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  if (config.VULN) {
    // VULNERABLE: username and password hash concatenated straight in.
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${sha256(password)}'`;
    try {
      const user = db.prepare(sql).get();
      if (user) {
        req.session.user = { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin };
        return res.redirect('/dashboard');
      }
      return res.render('login', { error: 'Invalid credentials', sqlShown: sql });
    } catch (e) {
      return res.render('login', { error: e.message, sqlShown: sql });
    }
  }
  // SAFE: parameterised, so injection in username is treated as literal text.
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password_hash = ?')
    .get(username, sha256(password));
  if (user) {
    req.session.user = { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin };
    return res.redirect('/dashboard');
  }
  res.render('login', { error: 'Invalid credentials', sqlShown: '' });
});

app.get('/register', (req, res) => res.render('register', { error: null }));

app.post('/register', (req, res) => {
  const { username = '', email = '', password = '' } = req.body;
  if (!config.VULN) {
    // SAFE: input validation.
    if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) return res.render('register', { error: 'Username must be 3-20 chars: letters, digits, underscore.' });
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.render('register', { error: 'Invalid email.' });
    if (String(password).length < 6) return res.render('register', { error: 'Password must be at least 6 characters.' });
  }
  try {
    // Parameterised in BOTH modes (registration is not an attack target here).
    db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?,?,?)')
      .run(username, email, sha256(password));
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    req.session.user = { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin };
    res.redirect('/dashboard');
  } catch (e) {
    res.render('register', { error: 'Could not register (username may be taken).' });
  }
});

app.get('/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });

// ---------------------------------------------------------------------------
// Dashboard + profile/settings (CSRF target: change email / password)
// ---------------------------------------------------------------------------
app.get('/dashboard', requireLogin, (req, res) => {
  const fresh = db.prepare('SELECT id, username, email, is_admin FROM users WHERE id = ?').get(req.session.user.id);
  res.render('dashboard', { me: fresh });
});

app.get('/profile', requireLogin, (req, res) => {
  const fresh = db.prepare('SELECT id, username, email, is_admin FROM users WHERE id = ?').get(req.session.user.id);
  res.render('profile', { me: fresh, notice: req.query.notice || '' });
});

// State-changing POSTs. CSRF-guarded only in SAFE mode.
app.post('/account/change-email', requireLogin, csrfGuard, (req, res) => {
  const email = req.body.email || '';
  if (!config.VULN && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.render('message', { title: 'Error', heading: 'Invalid email', text: 'Email failed validation.' });
  }
  db.prepare('UPDATE users SET email = ? WHERE id = ?').run(email, req.session.user.id);
  req.session.user.email = email;
  res.redirect('/profile?notice=' + encodeURIComponent('Email changed to ' + email));
});

app.post('/account/change-password', requireLogin, csrfGuard, (req, res) => {
  const password = req.body.password || '';
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(sha256(password), req.session.user.id);
  res.redirect('/profile?notice=' + encodeURIComponent('Password changed.'));
});

// ---------------------------------------------------------------------------
// PRODUCT PAGE + REVIEWS  -> Stored XSS (review body) + DOM XSS (location.hash)
// ---------------------------------------------------------------------------
app.get('/product/:id', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).render('message', { title: 'Not found', heading: 'No such product', text: '' });
  const reviews = db.prepare('SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC').all(product.id);
  res.render('product', { product, reviews });
});

app.post('/product/:id/review', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).render('message', { title: 'Not found', heading: 'No such product', text: '' });
  const author = (req.session.user && req.session.user.username) || req.body.author || 'guest';
  const body = req.body.body || '';
  const rating = parseInt(req.body.rating || '5', 10) || 5;
  // Review text is always stored verbatim; the difference is how it is RENDERED
  // (see views/product.ejs: <%- %> in VULN mode vs <%= %> in SAFE mode).
  db.prepare('INSERT INTO reviews (product_id, author, body, rating) VALUES (?,?,?,?)')
    .run(product.id, author, body, rating);
  res.redirect('/product/' + product.id);
});

// ---------------------------------------------------------------------------
app.listen(config.PORT, () => {
  console.log(`ShopSmart running in ${config.MODE} mode on http://localhost:${config.PORT}`);
});
