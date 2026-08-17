"""Target identifier validation.

Centralised rules for WatchTarget(kind, value) so frontend, REST, and
the future matching engine (phase 4) all agree on what is acceptable.

Hard rules:
  - CPE: must start with "cpe:2.3:" and split into 13 colon-separated
    components (per the CPE 2.3 binding spec). Vendor AND product must
    not both be wildcard ("*" or "-") — that would match every CVE and
    flood the alert pipeline.
  - PURL: must start with "pkg:<type>/<namespace?>/<name>[@version]".
    The type segment is required and must be one of the registered
    PURL types supported by OSV.dev (npm, pypi, maven, golang, cargo,
    nuget, gem, packagist, hex, conan, deb, rpm, alpine, github).
  - Keyword: 2..200 printable characters, no '*' alone, no leading
    '*' wildcard, no SQL/HTML metacharacters that could trip the
    matcher in phase 4.
"""

from __future__ import annotations

_PURL_TYPES = {
    "npm", "pypi", "maven", "golang", "cargo", "nuget",
    "gem", "packagist", "hex", "conan", "deb", "rpm",
    "alpine", "github", "composer", "swift", "pub", "cran",
}


class TargetValidationError(ValueError):
    pass


def validate_target(kind: str, value: str) -> str:
    """Return a normalised value. Raises TargetValidationError on failure."""
    v = (value or "").strip()
    if not v:
        raise TargetValidationError("Empty value")

    if kind == "cpe":
        return _validate_cpe(v)
    if kind == "purl":
        return _validate_purl(v)
    if kind == "keyword":
        return _validate_keyword(v)
    raise TargetValidationError(f"Unknown kind: {kind}")


def _validate_cpe(v: str) -> str:
    v = v.lower()
    if not v.startswith("cpe:2.3:"):
        raise TargetValidationError("CPE must start with 'cpe:2.3:'")
    parts = v.split(":")
    # cpe + 2.3 + part + vendor + product + version + update + edition +
    # language + sw_edition + target_sw + target_hw + other = 13 parts
    if len(parts) != 13:
        raise TargetValidationError("CPE 2.3 must have 13 colon-separated parts")
    part = parts[2]
    if part not in ("a", "o", "h", "*"):
        raise TargetValidationError("CPE part field must be a/o/h/*")
    vendor, product = parts[3], parts[4]
    if vendor in ("*", "-") and product in ("*", "-"):
        raise TargetValidationError("CPE vendor and product cannot both be wildcards")
    return v


def _validate_purl(v: str) -> str:
    if not v.startswith("pkg:"):
        raise TargetValidationError("PURL must start with 'pkg:'")
    rest = v[4:]
    if "/" not in rest:
        raise TargetValidationError("PURL must contain at least pkg:<type>/<name>")
    purl_type, _, after = rest.partition("/")
    purl_type = purl_type.strip().lower()
    if purl_type not in _PURL_TYPES:
        raise TargetValidationError(f"Unsupported PURL type '{purl_type}'")
    if not after:
        raise TargetValidationError("PURL is missing the package name")
    # Normalise type lowercase (per spec); keep name case-sensitive.
    return "pkg:" + purl_type + "/" + after


def _validate_keyword(v: str) -> str:
    if len(v) < 2:
        raise TargetValidationError("Keyword must be at least 2 characters")
    if len(v) > 200:
        raise TargetValidationError("Keyword too long (max 200 characters)")
    if v.strip("*") == "":
        raise TargetValidationError("Keyword cannot be only wildcards")
    if v.startswith("*") or v.startswith("%"):
        raise TargetValidationError("Keyword cannot start with a wildcard")
    forbidden = set("<>\";\\")
    if any(c in forbidden for c in v):
        raise TargetValidationError("Keyword contains invalid characters")
    return v
