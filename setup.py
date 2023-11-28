#!/usr/bin/env python

from typing import Sequence
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist
import os
import sys

with open(os.path.join(os.path.dirname(__file__), "VERSION"), encoding="utf-8") as ver_file:
    VERSION = ver_file.readline().strip()

with open("requirements.txt", encoding="utf-8") as reqs_file:
    requirements = reqs_file.read().splitlines()

with open("test-requirements.txt", encoding="utf-8") as reqs_file:
    test_requirements = reqs_file.read().splitlines()

with open("README.md", encoding="utf-8") as rm_file:
    long_description = rm_file.read()


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
                    line = line.replace('"git"', "'%s'" % VERSION)
                    found = True
                out.append(line)
    except OSError:
        print("Couldn't find file %s to stamp version" % filename, file=sys.stderr)

    if found:
        with open(filename, "w") as f:
            f.writelines(out)
    else:
        print("WARNING: Couldn't find version line in file %s" % filename, file=sys.stderr)


setup(
    name="GitPython",
    cmdclass={"build_py": build_py, "sdist": sdist},
    version=VERSION,
    description="GitPython is a Python library used to interact with Git repositories",
    author="Sebastian Thiel, Michael Trier",
    author_email="byronimo@gmail.com, mtrier@gmail.com",
    license="BSD-3-Clause",
    url="https://github.com/gitpython-developers/GitPython",
    packages=find_packages(exclude=["test", "test.*"]),
    include_package_data=True,
    package_dir={"git": "git"},
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={"test": test_requirements},
    zip_safe=False,
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        # Picked from
        #   http://pypi.python.org/pypi?:action=list_classifiers
        # "Development Status :: 1 - Planning",
        # "Development Status :: 2 - Pre-Alpha",
        # "Development Status :: 3 - Alpha",
        # "Development Status :: 4 - Beta",
        "Development Status :: 5 - Production/Stable",
        # "Development Status :: 6 - Mature",
        # "Development Status :: 7 - Inactive",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "Typing :: Typed",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
