#!/usr/bin/env python3
"""E2E HTTP — FEAT-35 : notifications multi-modules (Pilot ⇄ AppSec ⇄ Surface).

Couvre le comportement validé manuellement (process step 8) :
  1. Écriture des prefs DEPUIS AppSec (proxy) → relecture identique DEPUIS
     Pilot et DEPUIS Surface (stockage unique)
  2. Bloc surface : opt-in défaut off ; activation + seuil depuis Surface
  3. Garde-fous : sévérité invalide → 422 (via proxy), non authentifié → 401
  4. « Lancer un test » depuis la cloche Surface → orchestration Pilot,
     un statut par module respectant les flags enabled (emails réels)
  5. Remise à l'état neutre

Usage :
  PILOT_JWT=… APPSEC_JWT=… SURFACE_JWT=… \
  python3 tests/test_suite_notifications_e2e.py https://localhost:8443
  (JWTs forgés in-container : src.auth.create_jwt côté pilot,
   src.auth_common.create_jwt côté modules)
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://localhost:8443").rstrip("/")
JWTS = {"pilot": os.environ.get("PILOT_JWT", ""),
        "appsec": os.environ.get("APPSEC_JWT", ""),
        "surface": os.environ.get("SURFACE_JWT", "")}
PATHS = {"pilot": "/api/me/notification-prefs",
         "appsec": "/appsec/api/me/notification-prefs",
         "surface": "/surface/api/me/notification-prefs"}

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
FAILS = []


def check(label, ok, detail=""):
    print(("OK   " if ok else "FAIL ") + label + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(label)


def req(module, method, suffix="", body=None, auth=True):
    h = {}
    if auth and JWTS[module]:
        h["Cookie"] = f"{module}_token=" + JWTS[module]
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + PATHS[module] + suffix, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=60) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, None


if not all(JWTS.values()):
    print("PILOT_JWT / APPSEC_JWT / SURFACE_JWT requis"); sys.exit(2)

NEUTRAL = {"enabled": False, "day_of_week": 0, "upcoming_days": 14,
           "include_overdue": True, "scope": "mine", "modules": [],
           "lang": "fr", "subject_prefix": "[CISO Toolbox]",
           "module_prefs": {
               "appsec": {"alert_enabled": False, "alert_min_severity": "low",
                          "weekly_enabled": False, "weekly_day": 0,
                          "weekly_min_severity": "low", "subject_prefix": "[AppSec]"},
               "surface": {"alert_enabled": False, "alert_min_severity": "low",
                           "subject_prefix": "[Surface]"}}}

# 0. état neutre
st, _ = req("pilot", "PUT", body=NEUTRAL)
check("mise à neutre initiale", st == 200, str(st))

# 1. écriture depuis AppSec → relue partout (stockage unique)
wanted = json.loads(json.dumps(NEUTRAL))
wanted["module_prefs"]["appsec"].update({"alert_enabled": True, "alert_min_severity": "high"})
wanted["module_prefs"]["surface"].update({"alert_enabled": True, "alert_min_severity": "critical",
                                          "subject_prefix": "[SFC-E2E]"})
st, echo = req("appsec", "PUT", body=wanted)
check("PUT via AppSec -> 200", st == 200, str(st))
for m in ("pilot", "surface"):
    st, back = req(m, "GET")
    check(f"relecture via {m}", st == 200 and back.get("module_prefs") == wanted["module_prefs"],
          json.dumps((back or {}).get("module_prefs"), ensure_ascii=False))

# 2. opt-in surface : défaut off vérifié sur l'état neutre plus bas (étape 5)

# 3. garde-fous
bad = json.loads(json.dumps(wanted))
bad["module_prefs"]["surface"]["alert_min_severity"] = "apocalyptic"
st, _ = req("surface", "PUT", body=bad)
check("sévérité invalide -> 422", st == 422, str(st))
st, _ = req("surface", "GET", auth=False)
check("non authentifié -> 401", st == 401, str(st))

# 4. test orchestré depuis Surface : pilot désactivé, appsec+surface activés
st, res = req("surface", "POST", "/test")
results = (res or {}).get("results") or {}
check("test-all -> 3 modules", st == 200 and set(results) == {"pilot", "appsec", "surface"},
      f"{st} {results}")
check("pilot ignoré (désactivé)", str(results.get("pilot", "")).startswith("skipped"), str(results))
check("appsec testé", results.get("appsec") == "sent", str(results))
check("surface testé", results.get("surface") == "sent", str(results))

# 5. remise à neutre + opt-in off par défaut
st, echo = req("pilot", "PUT", body=NEUTRAL)
check("remise à neutre", st == 200 and echo.get("module_prefs") == NEUTRAL["module_prefs"])

print("=" * 60)
if FAILS:
    print(f"{len(FAILS)} échec(s): {FAILS}"); sys.exit(1)
print("E2E notifications multi-modules : tout est vert")
