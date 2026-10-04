#!/usr/bin/env python3
"""Build the SAST rule tree embedded in the AppSec image (FEAT-52).

    python3 prepare_rules.py <opengrep-rules checkout> <house rules dir> <dest>

<dest>/rules/  the security rules of the opengrep-rules snapshot: rule files
               only (no test targets, no tooling), with the repository's
               LICENSE (LGPL 2.1 + Commons Clause), which must travel with them
<dest>/house/  CISO Toolbox's own rules
<dest>/index.json
               local rule id → registry name. Opengrep names a local rule
               `<dirs>.<rule id>` relative to its working directory; the
               public registry (and every finding recorded with Semgrep)
               `<dirs>.<file>.<rule id>`. AppSec reports the registry name, so
               a rule keeps one name across engines.

Standard library only: the image's tools stage has no PyYAML.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

SKIP_TOP = {".github", "scripts", "stats"}
RULES_HEAD = re.compile(r"^rules:\s*$", re.M)
CATEGORY = re.compile(r"^\s+category:\s*['\"]?security['\"]?\s*$", re.M)
ITEM = re.compile(r"^(\s*)-(\s+(.*))?$")
ID_VALUE = re.compile(r"""^id:\s*['"]?([A-Za-z0-9_.-]+)['"]?\s*$""")


def rule_ids(text: str) -> list[str]:
    """Ids of the rules of one file: the `id` key of each item of the
    top-level `rules:` list, wherever it sits in the item (it is not always
    the first key, and the dash may stand alone on its line), never an `id`
    nested deeper."""
    return [rid for _, rid in rule_id_lines(text)]


def rule_id_lines(text: str) -> list[tuple[int, str]]:
    """(line number, id) of each rule id, as read by rule_ids()."""
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.rstrip() == "rules:") + 1
    except StopIteration:
        return []
    item_indent = None      # indentation of the dashes of the rules list
    key_indent = None       # indentation of the keys of the current rule
    ids: list[tuple[int, str]] = []
    for lineno, line in enumerate(lines[start:], start):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        m = ITEM.match(line)
        if item_indent is None:
            if not m:
                break
            item_indent = indent
        if m and indent == item_indent:            # a new rule
            rest = (m.group(3) or "").strip()
            if rest:
                key_indent = line.index(rest)
                candidate = rest
            else:
                key_indent = None                  # keys start on the next line
                continue
        elif indent < item_indent or (not m and indent == item_indent):
            break                                  # left the rules list (next top-level key)
        else:
            if key_indent is None:
                key_indent = indent
            if indent != key_indent:
                continue
            candidate = line.strip()
        mid = ID_VALUE.match(candidate)
        if mid:
            ids.append((lineno, mid.group(1)))
    return ids


def renamed(text: str, lineno: int, old: str, new: str) -> str:
    """The rule file with the id on line `lineno` (a rule's own `id`, as found
    by rule_id_lines) renamed from `old` to `new` — never an `id` elsewhere."""
    lines = text.split("\n")
    line = lines[lineno]
    pat = re.compile(r"^(\s*(?:-\s+)?id:\s*['\"]?)" + re.escape(old) + r"(['\"]?\s*)$")
    out, n = pat.subn(lambda m: m.group(1) + new + m.group(2), line)
    if n != 1:
        raise SystemExit(f"cannot rename rule {old!r} on line {lineno + 1}")
    lines[lineno] = out
    return "\n".join(lines)


def rule_files(root: Path, security_only: bool):
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if p.suffix not in (".yaml", ".yml") or ".test." in p.name:
            continue
        if rel.parts[0] in SKIP_TOP or rel.parts[0].startswith("."):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if not RULES_HEAD.search(text):
            continue
        if security_only and not CATEGORY.search(text):
            continue
        yield rel, text


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    src, house, dest = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    index: dict[str, str] = {}
    counts, renames = {}, 0
    for group, root, security_only in (("rules", src, True), ("house", house, False)):
        out = dest / group
        out.mkdir(parents=True, exist_ok=True)
        files = list(rule_files(root, security_only))
        # Opengrep names a local rule <dirs>.<id>: two files of one directory
        # declaring the same id would share one name (and one finding key).
        # Such an id is renamed <file>-<id> in the copy — its registry name,
        # <dirs>.<file>.<id>, was distinct all along.
        seen: dict[tuple, int] = {}
        for rel, text in files:
            for rid in rule_ids(text):
                seen[(rel.parent, rid)] = seen.get((rel.parent, rid), 0) + 1
        for rel, text in files:
            dirs = list(rel.parent.parts)
            for lineno, rid in rule_id_lines(text):
                local_id = rid
                if seen[(rel.parent, rid)] > 1:
                    local_id = f"{rel.stem}-{rid}"
                    text = renamed(text, lineno, rid, local_id)
                    renames += 1
                local = ".".join([group, *dirs, local_id])
                registry = ".".join(([] if group == "rules" else ["house"]) + [*dirs, rel.stem, rid])
                if local in index and index[local] != registry:
                    raise SystemExit(f"rule name clash left: {local}")
                index[local] = registry
            (out / rel).parent.mkdir(parents=True, exist_ok=True)
            (out / rel).write_text(text, encoding="utf-8")
        counts[group] = len(files)
    shutil.copy(src / "LICENSE", dest / "rules" / "LICENSE")
    (dest / "index.json").write_text(json.dumps(index, indent=0, sort_keys=True), encoding="utf-8")
    print(f"sast rules: {counts['rules']} upstream file(s), {counts['house']} house file(s), "
          f"{len(index)} rule id(s) indexed, {renames} renamed apart")
    return 0


if __name__ == "__main__":
    sys.exit(main())
