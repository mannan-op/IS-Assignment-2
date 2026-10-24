// DOM-based XSS demo.
// Reads the URL fragment (location.hash) — fully attacker-controlled and never
// sent to the server — and renders it into #promo.
//
// VULN mode: el.innerHTML = <untrusted>  -> markup/scripts can execute.
// SAFE mode: el.textContent = <untrusted> -> rendered as inert text.
(function () {
  var el = document.getElementById('promo');
  if (!el) return;
  var mode = el.getAttribute('data-mode');
  var raw = decodeURIComponent((location.hash || '').replace(/^#/, ''));
  if (!raw) return;
  if (mode === 'vuln') {
    el.innerHTML = raw;            // VULNERABLE
  } else {
    el.textContent = raw;          // SAFE
  }
})();
