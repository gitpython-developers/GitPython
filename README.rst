==========
GitPython
==========

GitPython is a python library used to interact with git repositories, high-level like git-porcelain, or low-level like git-plumbing.

It provides abstractions of git objects for easy access of repository data, and additionally allows you to access the git repository more directly using either a pure python implementation, or the faster, but more resource intensive git command implementation.

The object database implementation is optimized for handling large quantities of objects and large datasets, which is achieved by using low-level structures and data streaming.

REQUIREMENTS
============

* Git ( tested with 1.7.3.2 )
* Python Nose - used for running the tests
* Mock by Michael Foord used for tests. Requires 0.5

INSTALL
=======
If you have downloaded the source code:

.. code-block:: console

   $ python setup.py install

or if you want to obtain a copy more easily:

.. code-block:: console

   $ easy_install gitpython

A distribution package can be obtained for manual installation at:

http://pypi.python.org/pypi/GitPython

SOURCE
======

GitPython's git repo is available on GitHub, which can be browsed at:

https://github.com/gitpython-developers/GitPython

and cloned using:

.. code-block:: console

    $ git clone git://github.com/gitpython-developers/GitPython.git git-python


DOCUMENTATION
=============
The html-compiled documentation can be found at the following URL:

http://packages.python.org/GitPython/

MAILING LIST
============
http://groups.google.com/group/git-python

ISSUE TRACKER
=============
Issues are tracked on github:

https://github.com/gitpython-developers/GitPython/issues

LICENSE
=======

New BSD License.  See the LICENSE file.
