from typing import Sequence
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist
import fnmatch
import os
import sys

with open(os.path.join(os.path.dirname(__file__), "VERSION")) as v:
    VERSION = v.readline().strip()

with open("requirements.txt") as reqs_file:
    requirements = reqs_file.read().splitlines()

with open("test-requirements.txt") as reqs_file:
    test_requirements = reqs_file.read().splitlines()

with open("README.md") as rm_file:
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
        with open(filename, "r") as f:
            for line in f:
                if "__version__ =" in line:
                    line = line.replace("\"git\"", "'%s'" % VERSION)
                    found = True
                out.append(line)
    except OSError:
        print("Couldn't find file %s to stamp version" % filename, file=sys.stderr)

    if found:
        with open(filename, "w") as f:
            f.writelines(out)
    else:
        print("WARNING: Couldn't find version line in file %s" % filename, file=sys.stderr)


def build_py_modules(basedir: str, excludes: Sequence = ()) -> Sequence:
    # create list of py_modules from tree
    res = set()
    _prefix = os.path.basename(basedir)
    for root, _, files in os.walk(basedir):
        for f in files:
            _f, _ext = os.path.splitext(f)
            if _ext not in [".py"]:
                continue
            _f = os.path.join(root, _f)
            _f = os.path.relpath(_f, basedir)
            _f = "{}.{}".format(_prefix, _f.replace(os.sep, "."))
            if any(fnmatch.fnmatch(_f, x) for x in excludes):
                continue
            res.add(_f)
    return list(res)


setup(
    name="GitPython",
    cmdclass={"build_py": build_py, "sdist": sdist},
    version=VERSION,
    description="""GitPython is a python library used to interact with Git repositories""",
    author="Sebastian Thiel, Michael Trier",
    author_email="byronimo@gmail.com, mtrier@gmail.com",
    license="BSD",
    url="https://github.com/gitpython-developers/GitPython",
    packages=find_packages(exclude=["test", "test.*"]),
    include_package_data=True,
    py_modules=build_py_modules("./git", excludes=["git.ext.*"]),
    package_dir={"git": "git"},
    python_requires=">=3.7",
    install_requires=requirements,
    tests_require=requirements + test_requirements,
    zip_safe=False,
    long_description="""GitPython is a python library used to interact with Git repositories""",
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
    ],
)
