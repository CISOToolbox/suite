#!/usr/bin/env python3
"""E2E HTTP du module Audit (sans navigateur) — parcours complet validé.

Couvre le comportement validé manuellement (process step 8) :
  1. Santé, index, login servis via le proxy
  2. Cycle de vie d'un audit stocké : création, autosave (PUT blob),
     liste, duplication, suppression — avec nom/organisation/date
     dérivés de D.meta
  3. Import d'un fichier JSON de la version frontend (multipart)
  4. Actions correctives : création avec responsable + control_id,
     patch de statut, journal
  5. Intégration Pilot : /internal/stats et /internal/measures exigent
     le service token, source_id composite (MES-NNN@project), write-back
  6. Garde-fous : import JSON invalide → 422, /internal bloqué au proxy

Usage :
  AUDIT_JWT=$(podman exec ciso2-audit python3 -c "import sys; sys.path.insert(0,'/app'); \
      from src.auth_common import create_jwt; \
      print(create_jwt('<uuid>', '<email>', 'admin', {'audit': 'admin'}))") \
  SERVICE_TOKEN=... python3 tests/test_audit_e2e.py https://localhost:8443
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
import uuid

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://localhost:8443").rstrip("/")
JWT = os.environ.get("AUDIT_JWT", "")
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FAILS = []


def check(label, ok, detail=""):
    print(("OK   " if ok else "FAIL ") + label + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(label)


def req(method, path, body=None, ctype="application/json", auth=True, headers=None):
    h = dict(headers or {})
    if auth and JWT:
        h["Cookie"] = "audit_token=" + JWT
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.setdefault("Content-Type", ctype)
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=20) as resp:
            raw = resp.read()
            try:
                return resp.status, (json.loads(raw) if raw else None)
            except ValueError:
                return resp.status, None  # HTML (index, login…)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, None


def multipart(field, filename, content, ctype="application/json"):
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"{field}\"; "
            f"filename=\"{filename}\"\r\nContent-Type: {ctype}\r\n\r\n").encode() \
        + content + f"\r\n--{b}--\r\n".encode()
    return body, "multipart/form-data; boundary=" + b


FRONTEND_EXPORT = {
    "meta": {"name": "E2E MedSecure", "ref": "AUD-E2E-001", "date": "2026-08-01",
             "auditor": "E2E Bot", "scope": "E2E", "hds": "non"},
    "findings": {
        "A.5.1": {"status": "c", "preuve": "PSSI", "constats": "OK", "ecart_critere": "",
                  "ecart_constat": "", "ecart_cause": "", "ecart_action": "", "images": []},
        "A.8.24": {"status": "ncmaj", "preuve": "", "constats": "Clés en clair",
                   "ecart_critere": "A.8.24", "ecart_constat": "Pas de KMS",
                   "ecart_cause": "Budget", "ecart_action": "Déployer un KMS", "images": []},
    },
    "doc_review": {}, "planning": {"days": []},
}


def main():
    if not JWT:
        print("AUDIT_JWT manquant — voir l'usage en tête de fichier")
        sys.exit(2)

    # ── 1. Servi via le proxy ──
    st, _ = req("GET", "/audit/api/health", auth=False)
    check("santé via proxy", st == 200)
    st, _ = req("GET", "/audit/", auth=False)
    check("index servi", st == 200)
    st, _ = req("GET", "/audit/login.html", auth=False)
    check("login servi", st == 200)

    # ── 2. Cycle de vie d'un audit stocké ──
    st, created = req("POST", "/audit/api/projects", {"name": "", "data": FRONTEND_EXPORT})
    check("création (meta dérivée)", st == 201 and created and created["name"] == "E2E MedSecure — AUD-E2E-001"
          and created["audit_date"] == "2026-08-01", str(created)[:120])
    pid = created["id"]

    blob = dict(FRONTEND_EXPORT)
    blob["findings"] = dict(FRONTEND_EXPORT["findings"])
    blob["findings"]["A.5.2"] = {"status": "pp", "preuve": "", "constats": "à formaliser",
                                 "ecart_critere": "", "ecart_constat": "", "ecart_cause": "",
                                 "ecart_action": "", "images": []}
    st, updated = req("PUT", f"/audit/api/projects/{pid}", {"data": blob})
    check("autosave PUT blob", st == 200 and len(updated["data"]["findings"]) == 3)

    st, items = req("GET", "/audit/api/projects")
    check("liste des audits", st == 200 and any(str(p["id"]) == str(pid) for p in items))

    st, dup = req("POST", f"/audit/api/projects/{pid}/duplicate")
    check("duplication", st == 201 and dup["name"].endswith("(copie)"))
    st, _ = req("DELETE", f"/audit/api/projects/{dup['id']}")
    check("suppression (admin)", st == 204)

    # ── 3. Import d'un fichier frontend ──
    body, ctype = multipart("file", "ISO_Audit_export.json", json.dumps(FRONTEND_EXPORT).encode())
    st, imported = req("POST", "/audit/api/projects/import", body, ctype)
    check("import fichier frontend", st == 201 and imported["organization"] == "E2E MedSecure")

    body, ctype = multipart("file", "bad.json", b"not json at all {")
    st, _ = req("POST", "/audit/api/projects/import", body, ctype)
    check("import JSON invalide → 422", st == 422)

    # Régression (revue sécurité) : un rôle viewer ne peut pas créer
    # d'audit par import — même garde que la création.
    viewer_jwt = os.environ.get("AUDIT_VIEWER_JWT", "")
    if viewer_jwt:
        body, ctype = multipart("file", "t.json", json.dumps(FRONTEND_EXPORT).encode())
        st, _ = req("POST", "/audit/api/projects/import", body, ctype,
                    headers={"Cookie": "audit_token=" + viewer_jwt}, auth=False)
        check("import interdit au viewer → 403", st == 403)

    # ── 4. Actions correctives ──
    st, m = req("POST", f"/audit/api/projects/{pid}/measures",
                {"title": "Déployer un KMS", "control_id": "A.8.24",
                 "responsable": "E2E Owner", "echeance": "2026-12-31"})
    check("création action corrective", st == 201 and m["id"] == "MES-001"
          and m["responsable"] == "E2E Owner" and m["control_id"] == "A.8.24")

    st, m2 = req("PATCH", f"/audit/api/projects/{pid}/measures/{m['id']}",
                 {"statut": "en_cours",
                  "progress_log": [{"at": "2026-08-11", "by": "e2e", "text": "démarré"}]})
    check("patch statut + journal", st == 200 and m2["statut"] == "en_cours"
          and len(m2["progress_log"]) == 1)

    # ── 5. Intégration Pilot (accès direct conteneur exclu : via proxy = bloqué,
    #       via BASE_DIRECT si fourni) ──
    st, _ = req("GET", "/audit/api/internal/stats", auth=False)
    check("/internal bloqué au proxy (404)", st == 404)

    direct = os.environ.get("AUDIT_DIRECT_URL", "")
    if direct and SERVICE_TOKEN:
        def dreq(method, path, body=None, headers=None):
            h = dict(headers or {})
            h["X-Service-Token"] = SERVICE_TOKEN
            data = json.dumps(body).encode() if body is not None else None
            if data is not None:
                h["Content-Type"] = "application/json"
            r = urllib.request.Request(direct.rstrip("/") + path, data=data, headers=h, method=method)
            try:
                with urllib.request.urlopen(r, timeout=20) as resp:
                    raw = resp.read()
                    return resp.status, (json.loads(raw) if raw else None)
            except urllib.error.HTTPError as e:
                return e.code, None

        st, stats = dreq("GET", "/api/internal/stats")
        check("stats service-token", st == 200 and stats["entity_label"] == "Audits"
              and stats["measures"]["total"] >= 1)
        st, ms = dreq("GET", "/api/internal/measures")
        ours = [x for x in (ms or []) if str(pid) in x["source_id"]]
        check("export mesures (source_id composite)", st == 200 and len(ours) == 1
              and ours[0]["source_id"] == f"MES-001@{pid}" and ours[0]["status"] == "in_progress")
        st, _ = dreq("PATCH", "/api/internal/measures/" + f"MES-001@{pid}",
                     {"status": "completed"})
        check("write-back Pilot (composite id)", st == 200)
        st, m3 = req("GET", f"/audit/api/projects/{pid}/measures")
        check("write-back appliqué", st == 200 and m3[0]["statut"] == "termine")

    # ── 6. Nettoyage ──
    st, _ = req("DELETE", f"/audit/api/projects/{pid}")
    check("nettoyage audit e2e", st == 204)
    st, _ = req("DELETE", f"/audit/api/projects/{imported['id']}")
    check("nettoyage import e2e", st == 204)

    print("=" * 60)
    if FAILS:
        print(f"E2E AUDIT: {len(FAILS)} échec(s): {FAILS}")
        sys.exit(1)
    print("E2E AUDIT: OK")


if __name__ == "__main__":
    main()
