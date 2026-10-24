// Central mode switch for the whole app.
//
// VULN=true  -> VULNERABLE build: string-concatenated SQL, unescaped output,
//               no CSRF token, permissive cookies.
// VULN=false -> SAFE build: prepared statements, output encoding, CSRF tokens,
//               SameSite=Strict cookies, input validation.
//
// Default is VULNERABLE so the demo attacks "just work" out of the box for
// grading. Flip the env var to study the hardened version.
const raw = (process.env.VULN || 'true').toLowerCase();
const VULN = !(raw === 'false' || raw === '0' || raw === 'no');

module.exports = {
  VULN,
  MODE: VULN ? 'VULNERABLE' : 'SAFE',
  PORT: parseInt(process.env.PORT || '3000', 10),
};
