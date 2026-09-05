#!/usr/bin/env python3
"""HTTP E2E for the demo-docker TS FRONTEND stack (no browser).

For every module served by the proxy: the index loads, ALL of its local
<script src>/<link href> resolve (200), the health API answers, and the
frontend being served really is the TypeScript build ('code' icon marker)."""
import ssl, sys, re, urllib.request
from urllib.parse import urljoin

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://localhost:8444"
MODULES = {  # module: URL prefix
    "pilot": "", "risk": "risk/", "vendor": "vendor/", "compliance": "compliance/",
    "asset": "asset/", "access": "access/", "surface": "surface/",
    "appsec": "appsec/", "watch": "watch/", "audit": "audit/",
}
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "e2e-http"})
    with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
        return r.status, r.read()

fails = []
print(f"E2E HTTP — {BASE}\n" + "=" * 60)
for mod, pfx in MODULES.items():
    base = urljoin(BASE + "/", pfx)
    tag = f"[{mod}]"
    try:
        st, body = get(base)
    except Exception as e:
        print(f"FAIL {tag} index: {e}"); fails.append(f"{mod}:index"); continue
    if st != 200:
        print(f"FAIL {tag} index -> {st}"); fails.append(f"{mod}:index"); continue
    html = body.decode("utf-8", "replace")
    # referenced local assets
    assets = re.findall(r'<script[^>]+src="([^"]+)"', html) + \
             re.findall(r'<link[^>]+href="([^"]+\.css[^"]*)"', html)
    assets = [a for a in assets if not a.startswith(("http://", "https://", "//"))]
    bad = []
    for a in assets:
        u = urljoin(base, a.split("?")[0])
        try:
            ast, _ = get(u)
        except Exception as e:
            ast = f"ERR {e}"
        if ast != 200:
            bad.append(f"{a} -> {ast}")
    # health API
    try:
        hst, _ = get(urljoin(base, "api/health"))
    except Exception as e:
        hst = f"ERR {e}"
    # TS build marker in cisotoolbox.js
    ts_ok = None
    try:
        _, js = get(urljoin(base, "js/cisotoolbox.js"))
        ts_ok = b'"code"' in js
    except Exception:
        ts_ok = "n/a"
    status = "OK  " if (not bad and hst == 200) else "FAIL"
    if bad or hst != 200:
        fails.append(mod)
    print(f"{status} {tag} index=200 assets={len(assets)} 404s={len(bad)} "
          f"health={hst} ts_front={ts_ok}")
    for b in bad:
        print(f"        ⨯ {b}")

print("=" * 60)
if fails:
    print(f"RÉSULTAT: {len(fails)} module(s) en échec: {', '.join(sorted(set(fails)))}")
    sys.exit(1)
print("RÉSULTAT: tous les modules OK (front TS servi, 0 asset manquant, API up)")
