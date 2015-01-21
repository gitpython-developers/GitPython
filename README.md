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

### Live Coding

You can watch me fix issues or implement new features [live on Twitch][twitch-channel], or have a look at [past recordings on youtube][youtube-playlist]

* [Live on Twitch][twitch-channel] (just follow the channel to be notified when a session starts)
* [Archive on Youtube][youtube-playlist]

### INFRASTRUCTURE

* [User Documentation](http://gitpython.readthedocs.org)
* [Mailing List](http://groups.google.com/group/git-python)
* [Issue Tracker](https://github.com/gitpython-developers/GitPython/issues)

### LICENSE

New BSD License.  See the LICENSE file.

### DEVELOPMENT STATUS

[![Build Status](https://travis-ci.org/gitpython-developers/GitPython.svg?branch=0.3)](https://travis-ci.org/gitpython-developers/GitPython)
[![Coverage Status](https://coveralls.io/repos/gitpython-developers/GitPython/badge.png?branch=master)](https://coveralls.io/r/gitpython-developers/GitPython?branch=master)
[![Documentation Status](https://readthedocs.org/projects/gitpython/badge/?version=stable)](https://readthedocs.org/projects/gitpython/?badge=stable)
[![Issue Stats](http://www.issuestats.com/github/gitpython-developers/GitPython/badge/pr)](http://www.issuestats.com/github/gitpython-developers/GitPython)
[![Issue Stats](http://www.issuestats.com/github/gitpython-developers/GitPython/badge/issue)](http://www.issuestats.com/github/gitpython-developers/GitPython)

Now that there seems to be a massive user base, this should be motivation enough to let git-python return to a proper state, which means

* no open pull requests
* no open issues describing bugs

#### FUTURE GOALS

There has been a lot of work in the master branch, which is the direction I want git-python to go. Namely, it should be able to freely mix and match the back-end used, depending on your requirements and environment.

* make new master work similarly to 0.3, but with the option to swap for at least one additional backend
* make a 1.0 release
* add backends as required


[twitch-channel]: http://www.twitch.tv/byronimo/profile
[youtube-playlist]: https://www.youtube.com/playlist?list=PLMHbQxe1e9MnoEcLhn6Yhv5KAvpWkJbL0