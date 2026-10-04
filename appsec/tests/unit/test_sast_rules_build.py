"""The SAST rule tree built into the image (sast/prepare_rules.py) and the
SBOM of what the Opengrep binary bundles (sast/opengrep_sbom.py)."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "sast"))

import opengrep_sbom  # noqa: E402
import prepare_rules  # noqa: E402


def test_rule_ids_read_the_rules_list_only():
    assert prepare_rules.rule_ids("rules:\n- id: a\nother:\n- id: z\n") == ["a"]
    assert prepare_rules.rule_ids("rules:\n  - id: a\n    x: 1\n  - message: m\n    id: b\n") == ["a", "b"]
    assert prepare_rules.rule_ids("rules:\n -\n    id: s\n    metadata:\n      id: nested\n") == ["s"]


def _write(root: pathlib.Path, rel: str, rid: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"rules:\n  - id: {rid}\n    languages: [csharp]\n    severity: ERROR\n"
                 f"    message: m\n    pattern: f()\n    metadata:\n      category: security\n")


def test_rules_sharing_an_id_in_one_directory_get_distinct_names(tmp_path, monkeypatch):
    src, house, dest = tmp_path / "src", tmp_path / "house", tmp_path / "out"
    _write(src, "csharp/ssrf/web-client.yaml", "ssrf")
    _write(src, "csharp/ssrf/http-client.yaml", "ssrf")
    _write(src, "csharp/xss/razor.yaml", "razor-xss")
    (src / "LICENSE").write_text("notice")
    house.mkdir()
    monkeypatch.setattr(sys, "argv", ["prepare_rules.py", str(src), str(house), str(dest)])
    assert prepare_rules.main() == 0
    index = json.loads((dest / "index.json").read_text())
    assert index["rules.csharp.ssrf.web-client-ssrf"] == "csharp.ssrf.web-client.ssrf"
    assert index["rules.csharp.ssrf.http-client-ssrf"] == "csharp.ssrf.http-client.ssrf"
    assert index["rules.csharp.xss.razor-xss"] == "csharp.xss.razor.razor-xss"     # untouched
    assert "id: web-client-ssrf" in (dest / "rules/csharp/ssrf/web-client.yaml").read_text()
    assert (dest / "rules/LICENSE").read_text() == "notice"


def test_rename_touches_the_rule_id_only():
    text = ("rules:\n  - message: m\n    metadata:\n      id: ssrf\n"
            "    id: ssrf\n    pattern: f()\n")
    (lineno, rid), = prepare_rules.rule_id_lines(text)
    out = prepare_rules.renamed(text, lineno, rid, "web-client-ssrf")
    assert "      id: ssrf" in out and "    id: web-client-ssrf" in out


def test_sbom_lists_the_bundled_packages(tmp_path, monkeypatch):
    listing = tmp_path / "bundled.txt"
    listing.write_text("# how it was derived\nurllib3==2.7.0\nruamel.yaml==0.19.1\n")
    out = tmp_path / "bom.cdx.json"
    monkeypatch.setattr(sys, "argv", ["opengrep_sbom.py", str(listing), "1.30.0", str(out)])
    assert opengrep_sbom.main() == 0
    bom = json.loads(out.read_text())
    assert bom["bomFormat"] == "CycloneDX"
    assert [c["purl"] for c in bom["components"]] == ["pkg:pypi/urllib3@2.7.0", "pkg:pypi/ruamel.yaml@0.19.1"]
    assert bom["metadata"]["component"]["version"] == "1.30.0"


def test_the_shipped_listing_is_well_formed():
    listing = pathlib.Path(__file__).resolve().parents[2] / "sast" / "opengrep-bundled.txt"
    pins = [l for l in listing.read_text().splitlines() if l and not l.startswith("#")]
    assert pins and all("==" in p for p in pins)
    assert not any(p.startswith(("protobuf==", "setuptools==")) for p in pins)
