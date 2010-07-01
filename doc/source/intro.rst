.. _intro_toplevel:

==================
Overview / Install
==================

GitPython is a python library used to interact with git repositories, high-level like git-porcelain, or low-level like git-plumbing.

It provides abstractions of git objects for easy access of repository data, and additionally allows you to access the git repository more directly using either a pure python implementation, or the faster, but more resource intensive git command implementation.

The object database implementation is optimized for handling large quantities of objects and large datasets, which is achieved by using low-level structures and data streaming.

Requirements
============

* `Git`_ 1.7.0 or newer
    It should also work with older versions, but it may be that some operations
    involving remotes will not work as expected.
* `GitDB`_ - a pure python git database implementation

 * `async`_ - asynchronous task scheduling
 
* `Python Nose`_ - used for running the tests
* `Mock by Michael Foord`_ used for tests. Requires version 0.5

.. _Git: http://git-scm.com/
.. _Python Nose: http://code.google.com/p/python-nose/
.. _Mock by Michael Foord: http://www.voidspace.org.uk/python/mock.html
.. _GitDB: http://pypi.python.org/pypi/gitdb
.. _async: http://pypi.python.org/pypi/async

Installing GitPython
====================

Installing GitPython is easily done using
`setuptools`_. Assuming it is
installed, just run the following from the command-line:

.. sourcecode:: none

    # easy_install GitPython

This command will download the latest version of GitPython from the
`Python Package Index <http://pypi.python.org/pypi/GitPython>`_ and install it
to your system. More information about ``easy_install`` and pypi can be found
here:

* `setuptools`_
* `install setuptools <http://peak.telecommunity.com/DevCenter/EasyInstall#installation-instructions>`_
* `pypi <http://pypi.python.org/pypi/SQLAlchemy>`_

.. _setuptools: http://peak.telecommunity.com/DevCenter/setuptools

Alternatively, you can install from the distribution using the ``setup.py``
script:

.. sourcecode:: none

    # python setup.py install
    
.. note:: In this case, you have to manually install `GitDB`_ and `async`_ as well. It would be recommended to use the :ref:`git source repository <source-code-label>` in that case.

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

GitPython's git repo is available on Gitorious and GitHub, which can be browsed at:

 * http://gitorious.org/projects/git-python/
 * http://github.com/Byron/GitPython

and cloned using::

	$ git clone git://gitorious.org/git-python/mainline.git git-python
	$ git clone git://github.com/Byron/GitPython.git git-python
	
Initialize all submodules to obtain the required dependencies with::
    
    $ cd git-python
    $ git submodule update --init --recursive
    
Finally verify the installation by running the `nose powered <http://code.google.com/p/python-nose/>`_ unit tests::
    
    $ nosetests
    
Mailing List
============
http://groups.google.com/group/git-python

Issue Tracker
=============
http://byronimo.lighthouseapp.com/projects/51787-gitpython/milestones
	
License Information
===================
GitPython is licensed under the New BSD License.  See the LICENSE file for
more information.

