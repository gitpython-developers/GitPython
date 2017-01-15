## GitPython

GitPython is a python library used to interact with git repositories, high-level like git-porcelain,
or low-level like git-plumbing.

It provides abstractions of git objects for easy access of repository data, and additionally
allows you to access the git repository more directly using either a pure python implementation,
or the faster, but more resource intensive *git command* implementation.

The object database implementation is optimized for handling large quantities of objects and large datasets,
which is achieved by using low-level structures and data streaming.


### REQUIREMENTS

GitPython needs the `git` executable to be installed on the system and available
in your `PATH` for most operations.
If it is not in your `PATH`, you can help GitPython find it by setting
the `GIT_PYTHON_GIT_EXECUTABLE=<path/to/git>` environment variable.

* Git (1.7.x or newer)
* Python 2.7 to 3.5, while python 2.6 is supported on a *best-effort basis*.

The list of dependencies are listed in `./requirements.txt` and `./test-requirements.txt`.
The installer takes care of installing them for you.

### INSTALL

If you have downloaded the source code:

    python setup.py install

or if you want to obtain a copy from the Pypi repository:

    pip install GitPython

Both commands will install the required package dependencies.

A distribution package can be obtained for manual installation at:

    http://pypi.python.org/pypi/GitPython

If you like to clone from source, you can do it like so:

```bash
git clone https://github.com/gitpython-developers/GitPython
git submodule update --init --recursive
./init-tests-after-clone.sh
```

### Limitations

#### Leakage of System Resources

GitPython is not suited for long-running processes (like daemons) as it tends to
leak system resources. It was written in a time where destructors (as implemented
in the `__del__` method) still ran deterministically.

In case you still want to use it in such a context, you will want to search the
codebase for `__del__` implementations and call these yourself when you see fit.

Another way assure proper cleanup of resources is to factor out GitPython into a
separate process which can be dropped periodically.

#### Windows support

For *Windows*, we do regularly test it on [Appveyor CI](https://www.appveyor.com/)
but not all test-cases pass - you may help improve them by exploring
[Issue #525](https://github.com/gitpython-developers/GitPython/issues/525).

#### Python 2.6

Python 2.6 is supported on best-effort basis; which means that it is likely to deteriorate over time.

### RUNNING TESTS

*Important*: Right after cloning this repository, please be sure to have executed
the `./init-tests-after-clone.sh` script in the repository root. Otherwise
you will encounter test failures.

On *Windows*, make sure you have `git-daemon` in your PATH.  For MINGW-git, the `git-daemon.exe`
exists in `Git\mingw64\libexec\git-core\`; CYGWIN has no daemon, but should get along fine
with MINGW's.

The easiest way to run tests is by using [tox](https://pypi.python.org/pypi/tox)
a wrapper around virtualenv. It will take care of setting up environments with the proper
dependencies installed and execute test commands. To install it simply:

    pip install tox

Then run:

    tox


For more fine-grained control, you can use `nose`.

### Contributions

Please have a look at the [contributions file][contributing].

### INFRASTRUCTURE

* [User Documentation](http://gitpython.readthedocs.org)
* [Questions and Answers](http://stackexchange.com/filters/167317/gitpython)
 * Please post on stackoverflow and use the `gitpython` tag
* [Issue Tracker](https://github.com/gitpython-developers/GitPython/issues)
  * Post reproducible bugs and feature requests as a new issue.
    Please be sure to provide the following information if posting bugs:
    * GitPython version (e.g. `import git; git.__version__`)
    * Python version (e.g. `python --version`)
    * The encountered stack-trace, if applicable
    * Enough information to allow reproducing the issue

### How to make a new release

* Update/verify the version in the `VERSION` file
* Update/verify that the changelog has been updated
* Commit everything
* Run `git tag <version>` to tag the version in Git
* Run `make release`
* Finally, set the upcoming version in the `VERSION` file, usually be
  incrementing the patch level, and possibly by appending `-dev`. Probably you
  want to `git push` once more.

### LICENSE

New BSD License.  See the LICENSE file.

### DEVELOPMENT STATUS

[![codecov](https://codecov.io/gh/gitpython-developers/GitPython/branch/master/graph/badge.svg)](https://codecov.io/gh/gitpython-developers/GitPython)
[![Build Status](https://travis-ci.org/gitpython-developers/GitPython.svg)](https://travis-ci.org/gitpython-developers/GitPython)
[![Build status](https://ci.appveyor.com/api/projects/status/0f3pi3c00hajlrsd/branch/master?svg=true&passingText=windows%20OK&failingText=windows%20failed)](https://ci.appveyor.com/project/Byron/gitpython/branch/master)
[![Code Climate](https://codeclimate.com/github/gitpython-developers/GitPython/badges/gpa.svg)](https://codeclimate.com/github/gitpython-developers/GitPython)
[![Documentation Status](https://readthedocs.org/projects/gitpython/badge/?version=stable)](https://readthedocs.org/projects/gitpython/?badge=stable)
[![Stories in Ready](https://badge.waffle.io/gitpython-developers/GitPython.png?label=ready&title=Ready)](https://waffle.io/gitpython-developers/GitPython)
[![Throughput Graph](https://graphs.waffle.io/gitpython-developers/GitPython/throughput.svg)](https://waffle.io/gitpython-developers/GitPython/metrics/throughput)

Now that there seems to be a massive user base, this should be motivation enough to let git-python
return to a proper state, which means

* no open pull requests
* no open issues describing bugs

[contributing]: https://github.com/gitpython-developers/GitPython/blob/master/CONTRIBUTING.md
