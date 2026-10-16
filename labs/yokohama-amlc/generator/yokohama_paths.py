#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Locate the pkt-core toolkit from anywhere, without hardcoding a home path.

An env-var default such as ``os.environ.get("PKT_TOOLKIT", "/home/someone/...")``
is not enough on its own: it works on the author's machine and breaks for anyone
who does not set the variable.  This resolves the toolkit the way the build
scripts do --

1. an explicit ``PKT_TOOLKIT`` wins;
2. otherwise search upward from this file for a directory holding both
   ``tools/lab_api.py`` and ``src/pkt_core`` (which is also how the package
   behaves when it is vendored *inside* the toolkit, as ``generators/``);
3. otherwise fail with a message that says how to fix it.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

__all__ = ["find_toolkit", "bootstrap"]

_MESSAGE = """error: cannot find the pkt-core toolkit (tools/lab_api.py + src/pkt_core).

This package builds a lab; the toolkit does the encoding.  Clone it and either
set PKT_TOOLKIT or place this directory inside it:

    git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
    pip install -e packet-tracer-pkt-format
    export PKT_TOOLKIT="$PWD/packet-tracer-pkt-format"
"""


def find_toolkit(start: Path | None = None) -> Path:
    """Return the toolkit root, or exit with instructions."""
    env = os.environ.get("PKT_TOOLKIT")
    if env:
        p = Path(env).expanduser().resolve()
        if (p / "tools" / "lab_api.py").is_file() and (p / "src" / "pkt_core").is_dir():
            return p
        raise SystemExit(f"error: PKT_TOOLKIT={env} is not a pkt-core checkout "
                         "(expected tools/lab_api.py and src/pkt_core).")

    here = (start or Path(__file__).resolve().parent)
    for cand in [here, *here.parents]:
        if (cand / "tools" / "lab_api.py").is_file() and (cand / "src" / "pkt_core").is_dir():
            return cand
    raise SystemExit(_MESSAGE)


def bootstrap(start: Path | None = None) -> Path:
    """Put the toolkit, its ``tools/`` and its ``src/`` on ``sys.path``."""
    tk = find_toolkit(start)
    for p in (str(tk), str(tk / "tools"), str(tk / "src")):
        if p not in sys.path:
            sys.path.insert(0, p)
    return tk
