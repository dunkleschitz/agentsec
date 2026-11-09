#!/usr/bin/env python3
"""Build helper: copy tools/ into the agentsec wheel as tools_data/.

Runtime of the installed package stays standard-library-only. This file is
used only at build time (and is not imported by the CLI).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).parent
TOOLS_SRC = ROOT / "tools"
IGNORE = shutil.ignore_patterns(
    "__pycache__",
    "*.py[cod]",
    ".pytest_cache",
    ".mypy_cache",
    ".DS_Store",
)


def _copy_tools(dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(TOOLS_SRC, dest, ignore=IGNORE)


class BuildPy(build_py):
    def run(self):
        super().run()
        dest = Path(self.build_lib) / "agentsec" / "tools_data"
        self.announce("copying tools/ -> %s" % dest, level=2)
        _copy_tools(dest)


setup(cmdclass={"build_py": BuildPy})
