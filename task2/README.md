# ShopSmart — Web Security Practical (Part 2)

A deliberately **vulnerable** (and separately **hardened**) full-stack e-commerce
web application, built to demonstrate — and then defend against — the classic web
attacks: **Cross-Site Scripting (XSS)**, **Cross-Site Request Forgery (CSRF)** and
**SQL Injection (SQLi)**.

The *same* codebase runs in two modes controlled by one switch, so you can diff the
secure and insecure behaviour line-by-line.

> Academic use only. Run it locally. Never deploy the vulnerable mode anywhere public.

---

## Use case

**ShopSmart**, an online electronics store, with:

- Product catalogue + product detail pages
- User **registration / login / logout** (session cookies)
- **Product reviews/comments** (user-generated content)
- **Search**
- **Profile / account settings** with *change email* and *change password* actions
- An **admin** account

## Tech stack

| Layer     | Choice |
|-----------|--------|
| Runtime   | Node.js (v20) |
| Server    | Express 4 |
| Views     | EJS (server-rendered) + a little client JS |
| Database  | SQLite via `better-sqlite3` |
| Sessions  | `express-session` (cookie `sid`) |

---

## Install & run

```bash
cd part2
npm install          # installs express, ejs, better-sqlite3, express-session, cookie-parser
npm run seed         # builds shop.db from schema.sql + seed-data.sql
```

### Run the VULNERABLE version (attacks work)
```bash
npm run start:vuln         # VULN=true  -> http://localhost:3000
```

### Run the SAFE version (attacks blocked)
```bash
npm run start:safe         # VULN=false -> http://localhost:3000
```

`npm start` defaults to **vulnerable** mode.

> **Port note:** the app listens on port **3000** by default. If 3000 is busy,
> pick another port with `PORT`, e.g. `VULN=true PORT=3010 npm start`.
> All verification evidence in `evidence/` was captured on ports 3010 (vuln) and
> 3011 (safe) because port 3000 was already in use on the build machine.

### Toggling modes

The switch is the **`VULN` environment variable**, read in [`config.js`](./config.js):

- `VULN=true`  → `VULNERABLE` build
- `VULN=false` → `SAFE` build

Every route checks `config.VULN` and branches between the insecure and secure
implementation, and the EJS templates switch between unescaped `<%- %>` and
escaped `<%= %>` output. A coloured banner at the top of every page shows the
current mode.

### Demo accounts (from `seed-data.sql`)

| Username | Password   | Role  |
|----------|------------|-------|
| admin    | admin123   | admin |
| alice    | password1  | user  |
| bob      | hunter2    | user  |
| carol    | letmein    | user  |
| dave     | qwerty     | user  |

---

## Implemented vulnerabilities and their fixes

| # | Vulnerability | Where | Vulnerable implementation | Safe fix |
|---|---------------|-------|---------------------------|----------|
| 1 | **Reflected XSS** | `/search?q=` | search term echoed with `<%- q %>` (unescaped) | `<%= q %>` HTML-escaping + CSP |
| 2 | **Stored XSS** | product reviews | review body rendered with `<%- r.body %>` | `<%= r.body %>` escaping + CSP |
| 3 | **DOM-based XSS** | product page `#hash` | `public/js/dom.js` does `el.innerHTML = location.hash` | `el.textContent = …` (inert) |
| 4 | **CSRF** | `POST /account/change-email`, `/account/change-password` | no token, no SameSite restriction | synchronizer CSRF token + `SameSite=Strict` cookie + input validation |
| 5 | **SQLi — login bypass (easy)** | `POST /login` | username/hash concatenated into query | parameterised query |
| 6 | **SQLi — blind boolean (intermediate)** | `GET /api/user-exists?u=` | username concatenated into `WHERE` | parameterised query |
| 7 | **SQLi — UNION-based (advanced)** | `GET /search?q=` | term concatenated into `LIKE '%…%'` | parameterised `LIKE ?` |

Additional defence-in-depth in SAFE mode: input validation on register / change-email,
`httpOnly` cookies, and a Content-Security-Policy meta tag that blocks inline scripts.

See **[PAYLOADS.md](./PAYLOADS.md)** for every exact payload and curl-verified evidence.

---

## Project structure

```
part2/
├── app.js                 # Express app; all routes; vuln/safe branches
├── config.js              # VULN mode switch
├── db.js                  # SQLite open/seed helper
├── seed.js                # rebuild shop.db (npm run seed)
├── schema.sql             # table definitions
├── seed-data.sql          # realistic seed rows (users/products/reviews)
├── attacker.html          # CSRF proof-of-concept (auto-submitting form)
├── package.json
├── views/                 # EJS templates (header, footer, index, search,
│                          #   login, register, dashboard, profile, product, message)
├── public/
│   ├── css/style.css
│   └── js/dom.js          # DOM-XSS sink (innerHTML vs textContent)
├── evidence/              # curl transcripts proving each attack works / is blocked
└── README.md / PAYLOADS.md
```

## Browser-only caveats

The curl evidence proves the *server* behaviour (unescaped reflection, stored raw
markup, SQLi data exfiltration, the CSRF 403 vs success, SameSite). The actual
**JavaScript execution** (the `alert()` popups for reflected/stored/DOM XSS) and a
live cross-origin CSRF navigation need a **real browser** to observe/screenshot —
open the URLs in PAYLOADS.md to capture those.
