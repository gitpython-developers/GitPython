## GitPython

GitPython is a python library used to interact with git repositories, high-level like git-porcelain, or low-level like git-plumbing.

It provides abstractions of git objects for easy access of repository data, and additionally allows you to access the git repository more directly using either a pure python implementation, or the faster, but more resource intensive git command implementation.

The object database implementation is optimized for handling large quantities of objects and large datasets, which is achieved by using low-level structures and data streaming.

### REQUIREMENTS

* Git ( tested with 1.8.3.4 )
* Python Nose - used for running the tests
    -  Tested with nose 1.3.0
* Mock by Michael Foord used for tests
    - Tested with 1.0.1
* Coverage - used for tests coverage

The list of dependencies are listed in /requirements.txt and /test-requirements.txt. The installer takes care of installing them for you though.

### INSTALL

[![Latest Version](https://pypip.in/version/GitPython/badge.svg)](https://pypi.python.org/pypi/GitPython/)
[![Supported Python Versions](https://pypip.in/py_versions/GitPython/badge.svg)](https://pypi.python.org/pypi/GitPython/)

If you have downloaded the source code:

    python setup.py install

or if you want to obtain a copy from the Pypi repository:

    pip install gitpython

Both commands will install the required package dependencies.

A distribution package can be obtained for manual installation at:

    http://pypi.python.org/pypi/GitPython

### RUNNING TESTS

The easiest way to run test is by using [tox](https://pypi.python.org/pypi/tox) a wrapper around virtualenv. It will take care of setting up environnements with the proper dependencies installed and execute test commands. To install it simply:

    pip install tox

Then run:

    tox

### SOURCE

GitPython's git repo is available on GitHub, which can be browsed at [github](https://github.com/gitpython-developers/GitPython) and cloned like that:

    git clone git://github.com/gitpython-developers/GitPython.git git-python


### INFRASTRUCTURE

* [User Documentation](http://gitpython.readthedocs.org)
* [Mailing List](http://groups.google.com/group/git-python)
* [Issue Tracker](https://github.com/gitpython-developers/GitPython/issues)

### LICENSE

New BSD License.  See the LICENSE file.

### DEVELOPMENT STATUS

[![Build Status](https://travis-ci.org/gitpython-developers/GitPython.svg?branch=0.3)](https://travis-ci.org/gitpython-developers/GitPython)
[![Coverage Status](https://coveralls.io/repos/gitpython-developers/GitPython/badge.png?branch=0.3)](https://coveralls.io/r/gitpython-developers/GitPython?branch=0.3)
[![Documentation Status](https://readthedocs.org/projects/gitpython/badge/?version=stable)](https://readthedocs.org/projects/gitpython/?badge=stable)


The project was idle for 2 years, the last release (v0.3.2 RC1) was made on July 2011. Reason for this might have been the project's dependency on me as sole active maintainer, which is an issue in itself.

Now that there seems to be a massive user base, this should be motivation enough to let git-python return to a proper state, which means

* no open pull requests
* no open issues describing bugs

In short, I want to make a new release of 0.3 with all contributions and fixes included, foster community building to facilitate contributions.

#### PRESENT GOALS

The goals I have set for myself, in order, are as follows, all on branch 0.3.

* bring the test suite back online to work with the most commonly used git version
* merge all open pull requests, may there be a test-case or not, back. If something breaks, fix it if possible or let the contributor know
* conform git-python's structure and toolchain to the one used in my [other OSS projects](https://github.com/Byron/bcore)
* evaluate all open issues and close them if possible
* evaluate python 3.3 compatibility and establish it if possible

While that is happening, I will try hard to foster community around the project. This means being more responsive on the mailing list and in issues, as well as setting up clear guide lines about the [contribution](http://rfc.zeromq.org/spec:22) and maintenance workflow.

#### FUTURE GOALS

There has been a lot of work in the master branch, which is the direction I want git-python to go. Namely, it should be able to freely mix and match the back-end used, depending on your requirements and environment.

* restructure master to match my [OSS standard](https://github.com/Byron/bcore)
* review code base and bring test-suite back online
* establish python 3.3 compatibility
* make it work similarly to 0.3, but with the option to swap for at least one additional backend
* make a 1.0 release
* add backends as required
