.. _quickdoc_toplevel:

.. highlight:: python

.. _quickdoc-label:

==============================
GitPython Quick Start Tutorial
==============================

git.Repo
********

There are a few ways to create a :class:`git.Repo <git.repo.base.Repo>` object

An existing local path
######################

.. literalinclude:: ../../test/test_quick_doc.py
    :language: python
    :dedent: 8
    :start-after: # [1-test_init_repo_object]
    :end-before: # ![1-test_init_repo_object]

Existing local git Repo
#######################

.. literalinclude:: ../../test/test_quick_doc.py
    :language: python
    :dedent: 8
    :start-after: # [2-test_init_repo_object]
    :end-before: # ![2-test_init_repo_object]

Clone from URL
##############

For the rest of this tutorial we will use a clone from https://github.com