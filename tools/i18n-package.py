#!/usr/bin/env python3
"""Restrict the i18n languages embedded in an already-built module.

This is the packaging step that makes the languages modular: a deployment
that only wants English no longer embeds any French file, and vice versa.
Applied IN PLACE on a module's app/ directory (index.html + js/).

Usage:
    i18n-package.py <app_dir> --base en --langs en fr    # FR + EN, base EN
    i18n-package.py <app_dir> --base en --langs en        # EN only

Effects:
  - injects window._CT_BASE_LANG / window._CT_LANGS into index.html (before
    i18n.js): the engine knows the base language and the list to offer;
  - keeps the core + the module of the base language as STATIC <script>;
  - removes from the static set the <script> tags of the other RETAINED
    languages (they load lazily on the 1st switch, via _loadI18nFile);
  - deletes both the <script> tags AND the i18n_core_<lang>.js /
    *_i18n_<lang>.js files of the languages NOT retained.

Exits 0 if everything went well.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def _script_re(lang: str) -> re.Pattern:
    # <script src="js/i18n_core_<lang>.js"> and <script src="js/<Mod>_i18n_<lang>.js">
    return re.compile(
        r'[ \t]*<script src="js/(?:i18n_core_%s|[A-Za-z0-9_]+_i18n_%s)\.js"></script>\n'
        % (re.escape(lang), re.escape(lang))
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("app_dir", type=Path, help="a module's app/ directory")
    ap.add_argument("--base", required=True, help="base language (static, fallback)")
    ap.add_argument("--langs", nargs="+", required=True, help="retained languages (base included)")
    args = ap.parse_args()

    base = args.base
    retained = list(dict.fromkeys([base] + args.langs))  # base first, dedup, stable order
    app = args.app_dir
    jsdir = app / "js"
    index = app / "index.html"
    if not index.is_file():
        print(f"✗ index.html not found in {app}")
        return 1

    html = index.read_text(encoding="utf-8")

    # Candidate languages = those for which an i18n_core core file exists.
    all_langs = sorted({
        m.group(1) for f in jsdir.glob("i18n_core_*.js")
        if (m := re.search(r"i18n_core_([a-z]{2})\.js$", f.name))
    })

    removed_files: list[str] = []
    for lang in all_langs:
        rx = _script_re(lang)
        if lang not in retained:                     # excluded: scripts + files
            html = rx.sub("", html)
            for f in list(jsdir.glob(f"i18n_core_{lang}.js")) + list(jsdir.glob(f"*_i18n_{lang}.js")):
                f.unlink()
                removed_files.append(f.name)
        elif lang != base:                           # retained non-base: lazy (drop from the static set)
            html = rx.sub("", html)

    # Config injected just before i18n.js (so the engine reads it at load time).
    langs_js = "[" + ",".join(f'"{l}"' for l in retained) + "]"
    cfg = f'<script>window._CT_BASE_LANG="{base}";window._CT_LANGS={langs_js};</script>\n'
    html, n = re.subn(r'(<script src="js/i18n\.js"></script>\n)', cfg + r"\1", html, count=1)
    if n == 0:
        print("✗ <script src=\"js/i18n.js\"> tag not found — config not injected")
        return 1

    index.write_text(html, encoding="utf-8")
    print(f"✓ base={base}  retained={retained}")
    print(f"  removed files: {', '.join(removed_files) if removed_files else 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
