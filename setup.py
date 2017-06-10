#!/usr/bin/env python
from __future__ import print_function
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

from distutils.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist
import pkg_resources
import logging
import os
import sys
from os import path

with open(path.join(path.dirname(__file__), 'VERSION')) as v:
    VERSION = v.readline().strip()

with open('requirements.txt') as reqs_file:
    requirements = reqs_file.read().splitlines()


class build_py(_build_py):

    def run(self):
        init = path.join(self.build_lib, 'git', '__init__.py')
        if path.exists(init):
            os.unlink(init)
        _build_py.run(self)
        _stamp_version(init)
        self.byte_compile([init])


class sdist(_sdist):

    def make_release_tree(self, base_dir, files):
        _sdist.make_release_tree(self, base_dir, files)
        orig = path.join('git', '__init__.py')
        assert path.exists(orig), orig
        dest = path.join(base_dir, orig)
        if hasattr(os, 'link') and path.exists(dest):
            os.unlink(dest)
        self.copy_file(orig, dest)
        _stamp_version(dest)


def _stamp_version(filename):
    found, out = False, list()
    try:
        with open(filename, 'r') as f:
            for line in f:
                if '__version__ =' in line:
                    line = line.replace("'git'", "'%s'" % VERSION)
                    found = True
                out.append(line)
    except (IOError, OSError):
        print("Couldn't find file %s to stamp version" % filename, file=sys.stderr)

    if found:
        with open(filename, 'w') as f:
            f.writelines(out)
    else:
        print("WARNING: Couldn't find version line in file %s" % filename, file=sys.stderr)


install_requires = ['gitdb2 >= 2.0.0']
extras_require = {
    ':python_version == "2.6"': ['ordereddict'],
}
test_requires = ['ddt>=1.1.1']
if sys.version_info[:2] < (2, 7):
    test_requires.append('mock')

try:
    if 'bdist_wheel' not in sys.argv:
        for key, value in extras_require.items():
            if key.startswith(':') and pkg_resources.evaluate_marker(key[1:]):
                install_requires.extend(value)
except Exception:
    logging.getLogger(__name__).exception(
        'Something went wrong calculating platform specific dependencies, so '
        "you're getting them all!"
    )
    for key, value in extras_require.items():
        if key.startswith(':'):
            install_requires.extend(value)
# end

setup(
    name="GitPython",
    cmdclass={'build_py': build_py, 'sdist': sdist},
    version=VERSION,
    description="Python Git Library",
    author="Sebastian Thiel, Michael Trier",
    author_email="byronimo@gmail.com, mtrier@gmail.com",
    url="https://github.com/gitpython-developers/GitPython",
    packages=find_packages('.'),
    py_modules=['git.' + f[:-3] for f in os.listdir('./git') if f.endswith('.py')],
    package_data={'git.test': ['fixtures/*']},
    package_dir={'git': 'git'},
    license="BSD License",
    requires=['gitdb2 (>=2.0.0)'],
    install_requires=install_requires,
    test_requirements=test_requires + install_requires,
    zip_safe=False,
    long_description="""GitPython is a python library used to interact with Git repositories""",
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
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
    ]
)
