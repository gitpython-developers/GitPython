#!/usr/bin/env python

import os
from pathlib import Path
import sys
from typing import Sequence

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist


def _read_content(path: str) -> str:
    return (Path(__file__).parent / path).read_text(encoding="utf-8")


version = _read_content("VERSION").strip()


class build_py(_build_py):
    def run(self) -> None:
        init = os.path.join(self.build_lib, "git", "__init__.py")
        if os.path.exists(init):
            os.unlink(init)
        _build_py.run(self)
        _stamp_version(init)
        self.byte_compile([init])


class sdist(_sdist):
    def make_release_tree(self, base_dir: str, files: Sequence) -> None:
        _sdist.make_release_tree(self, base_dir, files)
        orig = os.path.join("git", "__init__.py")
        assert os.path.exists(orig), orig
        dest = os.path.join(base_dir, orig)
        if hasattr(os, "link") and os.path.exists(dest):
            os.unlink(dest)
        self.copy_file(orig, dest)
        _stamp_version(dest)


def _stamp_version(filename: str) -> None:
    found, out = False, []
    try:
        with open(filename) as f:
            for line in f:
                if "__version__ =" in line:
                    line = line.replace('"git"', "'%s'" % version)
                    found = True
                out.append(line)
    except OSError:
        print("Couldn't find file %s to stamp version" % filename, file=sys.stderr)

    if found:
        with open(filename, "w") as f:
            f.writelines(out)
    else:
        print("WARNING: Couldn't find version line in file %s" % filename, file=sys.stderr)


# See pyproject.toml for project metadata
setup(
    name="GitPython",
    cmdclass={"build_py": build_py, "sdist": sdist},
    license="BSD-3-Clause",
)
