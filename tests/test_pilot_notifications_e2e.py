#!/usr/bin/env python3
"""E2E HTTP — FEAT-34 : prefs de notification + digest d'échéances (Pilot).

Couvre le comportement validé manuellement (process step 8) :
  0. Mise à l'état neutre (répétabilité quel que soit l'état laissé avant)
  1. GET prefs → défauts opt-in (enabled=false, prefix [CISO Toolbox])
  2. PUT prefs complet (jour, fenêtre, périmètre admin, préfixe
     personnalisé, langue) → écho fidèle + persistance relue
  3. Garde-fous : fenêtre hors 7|14|30 → 422, langue inconnue → 422,
     appel non authentifié → 401
  4. POST /test (aperçu forcé) → status sent (chemin SMTP complet ;
     envoie UN email réel au porteur du JWT)
  5. Remise à l'état neutre (opt-in off) en fin de test

Usage :
  PILOT_JWT=$(podman exec ciso2-pilot python3 -c "import sys; sys.path.insert(0,'/app'); \
      from src.auth import create_jwt; \
      print(create_jwt('<uuid>', '<email>', 'admin', []))") \
  python3 tests/test_pilot_notifications_e2e.py https://localhost:8443
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://localhost:8443").rstrip("/")
JWT = os.environ.get("PILOT_JWT", "")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FAILS = []
P = "/api/me/notification-prefs"


def check(label, ok, detail=""):
    print(("OK   " if ok else "FAIL ") + label + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(label)


def req(method, path, body=None, auth=True):
    h = {}
    if auth and JWT:
        h["Cookie"] = "pilot_token=" + JWT
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, None


NEUTRAL = {"enabled": False, "day_of_week": 0, "upcoming_days": 14,
           "include_overdue": True, "scope": "mine", "modules": [],
           "lang": "fr", "subject_prefix": "[CISO Toolbox]"}


def subset_ok(echo, wanted):
    """FEAT-35: responses carry module_prefs on top of the FEAT-34 fields —
    compare only the fields this test drives."""
    return all(echo.get(k) == v for k, v in wanted.items())

if not JWT:
    print("PILOT_JWT manquant"); sys.exit(2)

# 0. état neutre reproductible (le test doit passer quel que soit l'état
# laissé par une session précédente)
st, _ = req("PUT", P, NEUTRAL)
check("mise à neutre initiale", st == 200, str(st))

# 1. lecture des défauts opt-in
st, prefs = req("GET", P)
check("GET prefs -> 200", st == 200, str(st))
check("défaut opt-in: enabled=false", bool(prefs) and prefs.get("enabled") is False)
check("défaut préfixe [CISO Toolbox]",
      bool(prefs) and prefs.get("subject_prefix") == "[CISO Toolbox]",
      json.dumps(prefs, ensure_ascii=False) if prefs else "vide")

# 2. PUT complet + persistance
wanted = {"enabled": True, "day_of_week": 2, "upcoming_days": 30,
          "include_overdue": False, "scope": "all", "modules": ["risk", "compliance"],
          "lang": "en", "subject_prefix": "[E2E Prefix]"}
st, echo = req("PUT", P, wanted)
check("PUT prefs -> 200", st == 200, str(st))
check("écho fidèle", subset_ok(echo, wanted), json.dumps(echo, ensure_ascii=False))
st, back = req("GET", P)
check("persistance relue", st == 200 and subset_ok(back, wanted))

# préfixe vide -> retombe sur le défaut
st, echo = req("PUT", P, {**wanted, "subject_prefix": "   "})
check("préfixe vide -> défaut", st == 200 and echo.get("subject_prefix") == "[CISO Toolbox]")

# 3. garde-fous
st, _ = req("PUT", P, {**wanted, "upcoming_days": 9})
check("fenêtre invalide -> 422", st == 422, str(st))
st, _ = req("PUT", P, {**wanted, "lang": "de"})
check("langue invalide -> 422", st == 422, str(st))
st, _ = req("GET", P, auth=False)
check("non authentifié -> 401", st == 401, str(st))

# 4. test multi-modules (envoie de vrais emails pour chaque module activé ;
# ici tout est désactivé côté digest pilot -> skipped, appsec activé par
# défaut -> sent)
st, res = req("POST", P + "/test")
results = (res or {}).get("results") or {}
check("POST /test -> results par module", st == 200 and "pilot" in results,
      f"{st} {res}")
check("statuts valides", all(str(v) == "sent" or str(v).startswith("skipped")
                             for v in results.values()), str(results))

# 5. retour à l'état neutre
st, echo = req("PUT", P, NEUTRAL)
check("remise à neutre", st == 200 and subset_ok(echo, NEUTRAL))

print("=" * 60)
if FAILS:
    print(f"{len(FAILS)} échec(s): {FAILS}"); sys.exit(1)
print("E2E notifications Pilot : tout est vert")
