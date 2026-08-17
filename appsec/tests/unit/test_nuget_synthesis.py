"""Regression: le scan de dépendances d'une application C#/.NET moderne était
silencieusement vide.

Trivy ne lit les dépendances NuGet que depuis packages.lock.json, *.deps.json
ou packages.config. Un projet SDK-style déclare ses PackageReference dans le
.csproj sans lockfile → run_trivy_fs rendait 0 vuln et une SBOM vide.
_synthesize_nuget_manifests() génère un packages.config par .csproj (versions
exactes uniquement) pour que trivy voie les dépendances.
"""
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.scanners import _synthesize_nuget_manifests  # noqa: E402


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


CSPROJ_SDK = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Serilog"><Version>2.10.0</Version></PackageReference>
    <PackageReference Include="RangePkg" Version="[4.0,5.0)" />
    <PackageReference Include="VarPkg" Version="$(SomeVar)" />
  </ItemGroup>
</Project>"""

CSPROJ_LEGACY_NS = """<?xml version="1.0" encoding="utf-8"?>
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <PackageReference Include="log4net" Version="2.0.8" />
  </ItemGroup>
</Project>"""


def _read_pkgs(path):
    tree = ET.parse(path)
    return {el.get("id"): el.get("version") for el in tree.getroot()}


def test_sdk_csproj_generates_packages_config(tmp_path):
    _write(tmp_path, "App/App.csproj", CSPROJ_SDK)
    assert _synthesize_nuget_manifests(str(tmp_path)) == 1
    pkgs = _read_pkgs(tmp_path / "App/packages.config")
    # versions exactes reprises, ranges et variables MSBuild ignorés
    assert pkgs == {"Newtonsoft.Json": "12.0.1", "Serilog": "2.10.0"}


def test_legacy_namespaced_csproj(tmp_path):
    _write(tmp_path, "Old/Old.csproj", CSPROJ_LEGACY_NS)
    assert _synthesize_nuget_manifests(str(tmp_path)) == 1
    assert _read_pkgs(tmp_path / "Old/packages.config") == {"log4net": "2.0.8"}


def test_existing_manifest_untouched(tmp_path):
    _write(tmp_path, "A/A.csproj", CSPROJ_SDK)
    existing = '<?xml version="1.0"?><packages><package id="x" version="1.0" /></packages>'
    _write(tmp_path, "A/packages.config", existing)
    _write(tmp_path, "B/B.csproj", CSPROJ_SDK)
    _write(tmp_path, "B/packages.lock.json", "{}")
    assert _synthesize_nuget_manifests(str(tmp_path)) == 0
    assert (tmp_path / "A/packages.config").read_text() == existing
    assert not (tmp_path / "B/packages.config").exists()


def test_central_package_management(tmp_path):
    _write(tmp_path, "Directory.Packages.props", """<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>""")
    _write(tmp_path, "App/App.csproj", """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup>
</Project>""")
    assert _synthesize_nuget_manifests(str(tmp_path)) == 1
    assert _read_pkgs(tmp_path / "App/packages.config") == {"Newtonsoft.Json": "13.0.1"}


DTD_BOMB = """<?xml version="1.0"?>
<!DOCTYPE Project [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<Project><ItemGroup>
  <PackageReference Include="P" Version="1.0.0" />
</ItemGroup></Project>"""


def test_dtd_rejected(tmp_path):
    # contenu non fiable : un .csproj avec DTD (XXE / billion-laughs) est ignoré
    _write(tmp_path, "Evil/Evil.csproj", DTD_BOMB)
    assert _synthesize_nuget_manifests(str(tmp_path)) == 0
    assert not (tmp_path / "Evil/packages.config").exists()


def test_dtd_rejected_utf16(tmp_path):
    # le rejet DTD doit tenir quel que soit l'encodage : en UTF-16 la
    # sous-chaîne d'octets b"<!DOCTYPE" n'apparaît pas (audit sécurité)
    p = tmp_path / "Evil16/Evil16.csproj"
    p.parent.mkdir(parents=True)
    p.write_bytes(DTD_BOMB.replace('"1.0"', '"1.0" encoding="utf-16"').encode("utf-16"))
    assert b"<!DOCTYPE" not in p.read_bytes()  # le vecteur du contournement
    assert _synthesize_nuget_manifests(str(tmp_path)) == 0
    assert not (tmp_path / "Evil16/packages.config").exists()


def test_symlinked_csproj_ignored(tmp_path):
    outside = tmp_path.parent / "outside.csproj"
    outside.write_text(CSPROJ_SDK)
    (tmp_path / "Sym").mkdir()
    (tmp_path / "Sym/App.csproj").symlink_to(outside)
    assert _synthesize_nuget_manifests(str(tmp_path)) == 0


def test_no_dotnet_repo_is_noop(tmp_path):
    _write(tmp_path, "src/app.py", "print('hello')")
    assert _synthesize_nuget_manifests(str(tmp_path)) == 0
