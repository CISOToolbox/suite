#!/usr/bin/env python3
"""A code finding keeps its identity when the file is edited around it.

The bug, reported from a real triage session: findings were keyed on
`file:line`, so adding or removing a line ABOVE a finding changed its key.
A finding marked false-positive lost that verdict and came back as new on
the next scan — the triage effort silently evaporated every time the file
was touched.

The identity is the matched CODE now, not its position. These tests pin the
three properties that follow, in the order that matters:

  1. the key survives a line shift (the bug),
  2. it changes when the matched code changes (a past verdict must not
     silence a different piece of code),
  3. two identical matches in one file stay two findings.

Pure stdlib, no scanner binary and no database: it parses fixture output
the way the scanners do.

NOTE: the fixtures below contain `os.system(...)` and `eval(...)` as plain
STRINGS — they stand for the vulnerable code a SAST rule matches, which is
the whole point of a scanner test. Nothing here is executed: the strings are
only ever hashed.

    python3 tests/unit/test_finding_identity.py
    pytest tests/unit/test_finding_identity.py
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from src.scanners import semgrep_finding  # noqa: E402


def _key(filepath: str, rule_id: str, snippet: str, line: int,
         seen: dict[str, int] | None = None) -> str:
    """Key produced by the PRODUCTION normalizer for one semgrep match.

    Takes the line, so a test that varies it proves the line is ignored —
    rather than re-deriving the key here and proving only that the test
    agrees with itself.
    """
    match = {"extra": {"lines": snippet, "severity": "ERROR", "message": ""},
             "start": {"line": line}}
    f = semgrep_finding(match, filepath, rule_id, line,
                        seen if seen is not None else {})
    return f["dedup_key"]


def test_key_survives_a_line_shift() -> list[str]:
    """THE bug: an import added at the top must not re-create the finding."""
    snippet = 'os.system(user_input)'
    at_12 = _key("app/main.py", "python.lang.security.audit", snippet, line=12)
    at_47 = _key("app/main.py", "python.lang.security.audit", snippet, line=47)
    if at_12 != at_47:
        return [f"key moved with the line: {at_12} != {at_47}"]
    return []


def test_key_changes_when_the_code_changes() -> list[str]:
    """A verdict on one snippet must not silence a different one."""
    a = _key("app/main.py", "rule.x", "os.system(user_input)", line=10)
    b = _key("app/main.py", "rule.x", "os.system(shlex.quote(user_input))", line=10)
    if a == b:
        return ["two different snippets share one key — a false-positive "
                "verdict would silence code that was never reviewed"]
    return []


def test_key_is_per_file() -> list[str]:
    """Same rule, same snippet, two files: two findings."""
    a = _key("app/a.py", "rule.x", "eval(x)", line=3)
    b = _key("app/b.py", "rule.x", "eval(x)", line=3)
    return [] if a != b else ["two files collapsed into one finding"]


def test_identical_matches_stay_distinct() -> list[str]:
    """Two identical matches in one file must remain two findings."""
    seen: dict[str, int] = {}
    first = _key("app/main.py", "rule.x", "eval(x)", line=3, seen=seen)
    second = _key("app/main.py", "rule.x", "eval(x)", line=9, seen=seen)
    return [] if first != second else ["two identical matches collapsed into one"]


def test_no_line_number_in_the_key() -> list[str]:
    """Belt and braces: a digit run that looks like a line must not appear."""
    key = _key("app/main.py", "rule.x", "eval(x)", line=42)
    return [] if ":42" not in key else ["a line number leaked into the key"]


CHECKS = (
    ("key survives a line shift", test_key_survives_a_line_shift),
    ("key changes with the code", test_key_changes_when_the_code_changes),
    ("key is per file", test_key_is_per_file),
    ("identical matches stay distinct", test_identical_matches_stay_distinct),
    ("no line number in the key", test_no_line_number_in_the_key),
)


def test_finding_identity() -> None:
    problems: list[str] = []
    for _, check in CHECKS:
        problems.extend(check())
    assert not problems, "finding identity broken:\n  " + "\n  ".join(problems)


def main() -> int:
    total = 0
    for label, check in CHECKS:
        problems = check()
        total += len(problems)
        print(f"{'FAIL' if problems else ' OK '}  {label}")
        for p in problems:
            print(f"        {p}")
    print(f"\n{total or 'no'} problem(s)")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
