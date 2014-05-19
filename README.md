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

### INSTALL

If you have downloaded the source code:

    python setup.py install
    
or if you want to obtain a copy more easily: 

    pip install gitpython
    
A distribution package can be obtained for manual installation at:

    http://pypi.python.org/pypi/GitPython

### DEVELOPMENT STATUS

[![Build Status](https://travis-ci.org/gitpython-developers/GitPython.svg?branch=0.3)](https://travis-ci.org/gitpython-developers/GitPython)
[![Coverage Status](https://coveralls.io/repos/gitpython-developers/GitPython/badge.png)](https://coveralls.io/r/gitpython-developers/GitPython)

The project was idle for 2 years, the last release was made about 3 years ago. Reason for this might have been the project's dependency on me as sole active maintainer, which is an issue in itself.

Now I am back and fully dedicated to pushing [OSS](https://github.com/Byron/bcore) forward in the realm of [digital content creation](http://gooseberry.blender.org/), and git-python will see some of my time as well. Therefore it will be moving forward, slowly but steadily.

In short, I want to make a new release of 0.3 with all contributions and fixes included, foster community building to facilitate contributions. Everything else is future.

#### PRESENT GOALS

The goals I have set for myself, in order, are as follows, all on branch 0.3.

* bring the test suite back online to work with the most commonly used git version
* setup a travis test-matrix to test against a lower and upper git version as well
* merge all open pull requests, may there be a test-case or not, back. If something breaks, fix it if possible or let the contributor know
* conform git-python's structure and toolchain to the one used in my [other OSS projects](https://github.com/Byron/bcore)
* evaluate all open issues and close them if possible
* create a new release of the 0.3 branch
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

### SOURCE


GitPython's git repo is available on GitHub, which can be browsed at:

https://github.com/gitpython-developers/GitPython

and cloned using:

git clone git://github.com/gitpython-developers/GitPython.git git-python


### DOCUMENTATION

The html-compiled documentation can be found at the following URL:

http://packages.python.org/GitPython/

### MAILING LIST

http://groups.google.com/group/git-python

### ISSUE TRACKER

Issues are tracked on github:

https://github.com/gitpython-developers/GitPython/issues

### LICENSE

New BSD License.  See the LICENSE file.
