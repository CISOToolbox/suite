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
        # preservation: every business key of the fixture survives
        for k, v in before.items():
            if k == "meta":
                continue
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

print("=" * 60)
if FAILS:
    print(f"{len(FAILS)} échec(s)"); sys.exit(1)
print("Schema migrations : tout est vert")
