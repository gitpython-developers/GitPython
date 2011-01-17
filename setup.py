#!/usr/bin/env python
try:
	from setuptools import setup, find_packages
except ImportError:
	from ez_setup import use_setuptools
	use_setuptools()
	from setuptools import setup, find_packages

from distutils.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist
import os
import sys
from os import path

v = open(path.join(path.dirname(__file__), 'VERSION'))
VERSION = v.readline().strip()
v.close()


class build_py(_build_py):
	def run(self):
		init = path.join(self.build_lib, 'git', '__init__.py')
		if path.exists(init):
			os.unlink(init)
		_build_py.run(self)
		_stamp_version(init)
		self.byte_compile([init])


class sdist(_sdist):
	def make_release_tree (self, base_dir, files):
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
		f = open(filename, 'r')
	except (IOError, OSError):
		print >> sys.stderr, "Couldn't find file %s to stamp version" % filename
		return
	#END handle error, usually happens during binary builds
	for line in f:
		if '__version__ =' in line:
			line = line.replace("'git'", "'%s'" % VERSION)
			found = True
		out.append(line)
	f.close()

	if found:
		f = open(filename, 'w')
		f.writelines(out)
		f.close()
	else:
		print >> sys.stderr, "WARNING: Couldn't find version line in file %s" % filename

setup(name = "GitPython",
	  cmdclass={'build_py': build_py, 'sdist': sdist},
	  version = VERSION,
	  description = "Python Git Library",
	  author = "Sebastian Thiel, Michael Trier",
	  author_email = "byronimo@gmail.com, mtrier@gmail.com",
	  url = "http://gitorious.org/projects/git-python/",
	  packages = find_packages('.'),
	  py_modules = ['git.'+f[:-3] for f in os.listdir('./git') if f.endswith('.py')],
	  package_data = {'git.test' : ['fixtures/*']},
	  package_dir = {'git':'git'},
	  license = "BSD License",
	  requires=('gitdb (>=0.5.1)',),
	  install_requires='gitdb >= 0.5.1',
	  zip_safe=False,
	  long_description = """\
GitPython is a python library used to interact with Git repositories""",
	  classifiers = [
		"Development Status :: 4 - Beta",
		"Intended Audience :: Developers",
		"License :: OSI Approved :: BSD License",
		"Operating System :: OS Independent",
		"Programming Language :: Python",
		"Programming Language :: Python :: 2.5",
		"Programming Language :: Python :: 2.6",
		"Topic :: Software Development :: Libraries :: Python Modules",
		]
	  )
