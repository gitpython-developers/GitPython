.. _intro_toplevel:

==================
Overview / Install
==================

GitPython is a python library used to interact with Git repositories.

GitPython is a port of the grit_ library in Ruby created by
Tom Preston-Werner and Chris Wanstrath.

.. _grit: http://grit.rubyforge.org

Requirements
============

* Git_ tested with 1.5.3.7
* `Python Nose`_ - used for running the tests
* `Mock by Michael Foord`_ used for tests. Requires 0.5 or higher

.. _Git: http://git-scm.com/
.. _Python Nose: http://code.google.com/p/python-nose/
.. _Mock by Michael Foord: http://www.voidspace.org.uk/python/mock.html

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

Getting Started
===============

* :ref:`tutorial_toplevel` - This tutorial provides a walk-through of some of
  the basic functionality and concepts used in GitPython. It, however, is not
  exhaustive so you are encouraged to spend some time in the
  :ref:`api_reference_toplevel`.

API Reference
=============

An organized section of the GitPthon API is at :ref:`api_reference_toplevel`.

Source Code
===========

GitPython's git repo is available on Gitorious, which can be browsed at:

http://gitorious.org/projects/git-python/

and cloned from:

git://gitorious.org/git-python/mainline.git

License Information
===================

GitPython is licensed under the New BSD License.  See the LICENSE file for
more information.

