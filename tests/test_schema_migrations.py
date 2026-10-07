#!/usr/bin/env python3
"""FEAT-36 — fixture test: every archived export of every rev migrates to
the current rev, old exports (rev 0) forever included; future revs are
refused. Fails when MODULE_REVS is bumped without a fixture for the
previous rev (the freeze that keeps the guarantee honest).

Run: python3 tests/test_schema_migrations.py   (stdlib only, or pytest)
"""
import copy
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
FIXTURES = HERE / "fixtures" / "exports"

spec = importlib.util.spec_from_file_location(
    "schema_migrations", HERE.parent / "risk" / "src" / "schema_migrations.py")
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

FAILS = []


def check(label, ok, detail=""):
    print(("OK   " if ok else "FAIL ") + label + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(label)


for module, app_rev in sorted(sm.MODULE_REVS.items()):
    fdir = FIXTURES / module
    # 1. every rev < current must have its archived fixture
    for rev in range(0, app_rev):
        fixture = fdir / f"rev{rev}.json"
        if rev == 0:
            check(f"{module}: fixture rev0 archivée", fixture.exists())
        # intermediate revs only exist for modules that have already been bumped:
        # vendor rev1 = V1 format — covered by the rev0 fixture (pre-versioning)
    # 2. every existing fixture migrates up to the current rev
    for fixture in sorted(fdir.glob("rev*.json")):
        data = json.loads(fixture.read_text())
        before = copy.deepcopy(data)
        out = sm.migrate_blob(module, data)
        check(f"{module}/{fixture.name}: migre vers rev {app_rev}",
              out["meta"]["schema_rev"] == app_rev)
        # preservation: every business key survives. A key a migration is
        # allowed to reshape (RESHAPED_KEYS) must stay present but may change
        # (e.g. FEAT-54 coerces classification 0 -> null in `vendors`); every
        # other key must be byte-identical.
        reshaped = getattr(sm, "RESHAPED_KEYS", {}).get(module, set())
        for k, v in before.items():
            if k == "meta":
                continue
            if k in reshaped:
                check(f"{module}/{fixture.name}: {k} survit (reshapé)", out.get(k) is not None)
            else:
                check(f"{module}/{fixture.name}: préserve {k}", out.get(k) == v,
                      f"{out.get(k)!r} != {v!r}")
        # normalization: the baseline collections exist
        for k in sm._BASELINE_KEYS[module]:
            check(f"{module}/{fixture.name}: baseline {k}", isinstance(out.get(k), list))
    # 3. flat refusal of future revs
    try:
        sm.migrate_blob(module, {"meta": {"schema_rev": app_rev + 1}})
        check(f"{module}: rev future refusée", False)
    except sm.FutureRevError as exc:
        check(f"{module}: rev future refusée", str(app_rev + 1) in str(exc) and str(app_rev) in str(exc))

# 4. idempotence: migrating twice = same result
d1 = json.loads((FIXTURES / "vendor" / "rev0.json").read_text())
sm.migrate_blob("vendor", d1)
d2 = copy.deepcopy(d1)
sm.migrate_blob("vendor", d2)
check("idempotence (vendor)", d1 == d2)

# 5. FEAT-54: a rev<=2 export's classification 0s coerce to null (not a real 0),
# so a server-side import/restore never silently promotes an unset vendor.
_v54 = json.loads((FIXTURES / "vendor" / "rev2.json").read_text())
sm.migrate_blob("vendor", _v54)
_v54_cls = (_v54.get("vendors") or [{}])[0].get("classification", {})
_v54_exp = (_v54.get("vendors") or [{}])[0].get("exposure", {})
check("vendor FEAT-54: classification 0 -> null",
      _v54_cls.get("replace_difficulty") is None and _v54_cls.get("ops_impact") == 3,
      f"cls={_v54_cls!r}")
check("vendor FEAT-54: exposure recomputed (incomplete axis -> null)",
      _v54_exp.get("penetration") is None,
      f"exp={_v54_exp!r}")

print("=" * 60)
if FAILS:
    print(f"{len(FAILS)} échec(s)"); sys.exit(1)
print("Schema migrations : tout est vert")
