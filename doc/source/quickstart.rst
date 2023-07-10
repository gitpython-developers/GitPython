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

$ git init path/to/dir

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

For the rest of this tutorial we will use a clone from https://github.com/LeoDaCoda/GitPython-TestFileSys.git

git clone https://some_repo_url

.. literalinclude:: ../../test/test_quick_doc.py
    :language: python
    :dedent: 8
    :start-after: # [1-test_cloned_repo_object]
    :end-before: # ![1-test_cloned_repo_object]

Usage
****************

* $ git add filepath

.. literalinclude:: ../../test/test_quick_doc.py
    :language: python
    :dedent: 8
    :start-after: # [2-test_cloned_repo_object]
    :end-before: # ![2-test_cloned_repo_object]

Now lets add the updated file to git

.. literalinclude:: ../../test/test_quick_doc.py
    :language: python
    :dedent: 8
    :start-after: # [3-test_cloned_repo_object]
    :end-before: # ![3-test_cloned_repo_object]

Notice the add method requires a list as a parameter

* $ git commit -m message

.. literalinclude:: ../../test/test_quick_doc.py
    :language: python
    :dedent: 8
    :start-after: # [4-test_cloned_repo_object]
    :end-before: # ![4-test_cloned_repo_object]

* $ git log file

A list of commits associated with a file

.. literalinclude:: ../../test/test_quick_doc.py
    :language: python
    :dedent: 8
    :start-after: # [5-test_cloned_repo_object]
    :end-before: # ![5-test_cloned_repo_object]

Notice this returns a generator object

.. literalinclude:: ../../test/test_quick_doc.py
    :language: python
    :dedent: 8
    :start-after: # [6-test_cloned_repo_object]
    :end-before: # ![6-test_cloned_repo_object]

returns list of :class:`Commit <git.objects.commit.Commit>` objects

* $ git status

    * Untracked files

    Lets create a new file

    .. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [7-test_cloned_repo_object]
        :end-before: # ![7-test_cloned_repo_object]

    .. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [8-test_cloned_repo_object]
        :end-before: # ![8-test_cloned_repo_object]

    * Modified files

    .. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [9-test_cloned_repo_object]
        :end-before: # ![9-test_cloned_repo_object]

    .. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [10-test_cloned_repo_object]
        :end-before: # ![10-test_cloned_repo_object]

    returns a list of :class:`Diff <git.diff.Diff>` objects

    .. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [11-test_cloned_repo_object]
        :end-before: # ![11-test_cloned_repo_object]


Trees & Blobs
**************

Latest Commit Tree
##################

.. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [12-test_cloned_repo_object]
        :end-before: # ![12-test_cloned_repo_object]

Any Commit Tree
###############

.. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [13-test_cloned_repo_object]
        :end-before: # ![13-test_cloned_repo_object]

Display level 1 Contents
########################

.. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [14-test_cloned_repo_object]
        :end-before: # ![14-test_cloned_repo_object]

Recurse through the Tree
########################

.. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [15-test_cloned_repo_object]
        :end-before: # ![15-test_cloned_repo_object]

.. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [16-test_cloned_repo_object]
        :end-before: # ![16-test_cloned_repo_object]




Printing text files
####################

.. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [17-test_cloned_repo_object]
        :end-before: # ![17-test_cloned_repo_object]

.. literalinclude:: ../../test/test_quick_doc.py
        :language: python
        :dedent: 8
        :start-after: # [18-test_cloned_repo_object]
        :end-before: # ![18-test_cloned_repo_object]



