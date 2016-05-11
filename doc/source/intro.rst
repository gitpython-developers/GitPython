.. _intro_toplevel:

==================
Overview / Install
==================

GitPython is a python library used to interact with git repositories, high-level like git-porcelain, or low-level like git-plumbing.

It provides abstractions of git objects for easy access of repository data, and additionally allows you to access the git repository more directly using either a pure python implementation, or the faster, but more resource intensive git command implementation.

The object database implementation is optimized for handling large quantities of objects and large datasets, which is achieved by using low-level structures and data streaming.

Requirements
============

* `Python`_ 2.7 or newer
    Since GitPython 2.0.0
* `Git`_ 1.7.0 or newer
    It should also work with older versions, but it may be that some operations
    involving remotes will not work as expected.
* `GitDB`_ - a pure python git database implementation
* `Python Nose`_ - used for running the tests
* `Mock by Michael Foord`_ used for tests. Requires version 0.5

.. _Python: https://www.python.org
.. _Git: https://git-scm.com/
.. _Python Nose: https://nose.readthedocs.io/en/latest/
.. _Mock by Michael Foord: http://www.voidspace.org.uk/python/mock.html
.. _GitDB: https://pypi.python.org/pypi/gitdb

Installing GitPython
====================

Installing GitPython is easily done using
`pip`_. Assuming it is
installed, just run the following from the command-line:

.. sourcecode:: none

    # pip install gitpython

This command will download the latest version of GitPython from the
`Python Package Index <http://pypi.python.org/pypi/GitPython>`_ and install it
to your system. More information about ``pip`` and pypi can be found
here:

* `install pip <https://pip.pypa.io/en/latest/installing.html>`_
* `pypi <https://pypi.python.org/pypi/GitPython>`_

.. _pip: https://pip.pypa.io/en/latest/installing.html

Alternatively, you can install from the distribution using the ``setup.py``
script:

.. sourcecode:: none

    # python setup.py install

.. note:: In this case, you have to manually install `GitDB`_ as well. It would be recommended to use the :ref:`git source repository <source-code-label>` in that case.

Getting Started
===============

* :ref:`tutorial-label` - This tutorial provides a walk-through of some of
  the basic functionality and concepts used in GitPython. It, however, is not
  exhaustive so you are encouraged to spend some time in the
  :ref:`api_reference_toplevel`.

API Reference
=============

An organized section of the GitPthon API is at :ref:`api_reference_toplevel`.

.. _source-code-label:

Source Code
===========

GitPython's git repo is available on GitHub, which can be browsed at:

 * https://github.com/gitpython-developers/GitPython

and cloned using::

	$ git clone https://github.com/gitpython-developers/GitPython git-python

Initialize all submodules to obtain the required dependencies with::

    $ cd git-python
    $ git submodule update --init --recursive

Finally verify the installation by running the `nose powered <http://code.google.com/p/python-nose/>`_ unit tests::

    $ nosetests

Questions and Answers
=====================
Please use stackoverflow for questions, and don't forget to tag it with `gitpython` to assure the right people see the question in a timely manner.

http://stackoverflow.com/questions/tagged/gitpython

Issue Tracker
=============
The issue tracker is hosted by github:

https://github.com/gitpython-developers/GitPython/issues

License Information
===================
GitPython is licensed under the New BSD License.  See the LICENSE file for
more information.

