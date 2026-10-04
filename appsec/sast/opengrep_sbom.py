#!/usr/bin/env python3
"""CycloneDX SBOM of what the Opengrep binary bundles.

    python3 opengrep_sbom.py <opengrep-bundled.txt> <opengrep version> <out.cdx.json>

The Opengrep release binary unpacks its own Python runtime and libraries with
no package metadata, so an image scanner sees nothing inside it.
opengrep-bundled.txt lists the Python packages it compiles in (`name==version`,
how it was derived is written at its top); written as a CycloneDX file in the
image, it lets trivy (image scan) report their vulnerabilities like any other
package. Standard library only.
"""
from __future__ import annotations

import json
import re
import sys
import uuid

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;#]+)")


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    listing, version, out = sys.argv[1], sys.argv[2], sys.argv[3]
    root = {
        "type": "application", "name": "opengrep", "version": version,
        "bom-ref": f"pkg:github/opengrep/opengrep@v{version}",
        "purl": f"pkg:github/opengrep/opengrep@v{version}",
    }
    components = []
    for line in open(listing, encoding="utf-8"):
        m = PIN.match(line.strip())
        if not m:
            continue
        # purl type pypi: lower case, "_" → "-", the dot kept (ruamel.yaml) —
        # advisories filed under a dotted name are matched under it.
        name = m.group(1).lower().replace("_", "-")
        purl = f"pkg:pypi/{name}@{m.group(2)}"
        components.append({"type": "library", "name": name, "version": m.group(2),
                           "bom-ref": purl, "purl": purl})
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'opengrep@' + version)}",
        "metadata": {"component": root},
        "components": components,
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=1)
    print(f"opengrep sbom: {len(components)} bundled package(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
