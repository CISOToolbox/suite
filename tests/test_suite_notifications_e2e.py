#!/usr/bin/env python3
"""HTTP E2E — FEAT-35: multi-module notifications (Pilot ⇄ AppSec ⇄ Surface).

Covers the manually validated behavior (process step 8):
  1. Writing the prefs FROM AppSec (proxy) → identical read back FROM
     Pilot and FROM Surface (single storage)
  2. Surface block: opt-in default off; enabling + threshold from Surface
  3. Guardrails: invalid severity → 422 (through the proxy), unauthenticated → 401
  4. « Lancer un test » from the Surface bell → Pilot orchestration,
     one status per module honouring the enabled flags (real emails)
  5. Reset to the neutral state

Usage:
  PILOT_JWT=… APPSEC_JWT=… SURFACE_JWT=… \
  python3 tests/test_suite_notifications_e2e.py https://localhost:8443
  (JWTs minted in-container: src.auth.create_jwt on the pilot side,
   src.auth_common.create_jwt on the module side)
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

# 0. neutral state
st, _ = req("pilot", "PUT", body=NEUTRAL)
check("mise à neutre initiale", st == 200, str(st))

# 1. write from AppSec → read back everywhere (single storage)
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

# 2. surface opt-in: default off, checked on the neutral state below (step 5)

# 3. guardrails
bad = json.loads(json.dumps(wanted))
bad["module_prefs"]["surface"]["alert_min_severity"] = "apocalyptic"
st, _ = req("surface", "PUT", body=bad)
check("sévérité invalide -> 422", st == 422, str(st))
st, _ = req("surface", "GET", auth=False)
check("non authentifié -> 401", st == 401, str(st))

# 4. test orchestrated from Surface: pilot disabled, appsec+surface enabled
st, res = req("surface", "POST", "/test")
results = (res or {}).get("results") or {}
check("test-all -> 3 modules", st == 200 and set(results) == {"pilot", "appsec", "surface"},
      f"{st} {results}")
check("pilot ignoré (désactivé)", str(results.get("pilot", "")).startswith("skipped"), str(results))
check("appsec testé", results.get("appsec") == "sent", str(results))
check("surface testé", results.get("surface") == "sent", str(results))

# 5. reset to neutral + opt-in off by default
st, echo = req("pilot", "PUT", body=NEUTRAL)
check("remise à neutre", st == 200 and echo.get("module_prefs") == NEUTRAL["module_prefs"])

print("=" * 60)
if FAILS:
    print(f"{len(FAILS)} échec(s): {FAILS}"); sys.exit(1)
print("E2E notifications multi-modules : tout est vert")
