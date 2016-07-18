.. _tutorial_toplevel:

.. highlight:: python

.. _tutorial-label:

==================
GitPython Tutorial
==================

GitPython provides object model access to your git repository. This tutorial is composed of multiple sections, most of which explains a real-life usecase.

All code presented here originated from `test_docs.py <https://github.com/gitpython-developers/GitPython/blob/master/git/test/test_docs.py>`_ to assure correctness. Knowing this should also allow you to more easily run the code for your own testing purposes, all you need is a developer installation of git-python.

Meet the Repo type
******************

The first step is to create a :class:`git.Repo <git.repo.base.Repo>` object to represent your repository.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [1-test_init_repo_object]
    :end-before: # ![1-test_init_repo_object]

In the above example, the directory ``self.rorepo.working_tree_dir`` equals ``/Users/mtrier/Development/git-python`` and is my working repository which contains the ``.git`` directory. You can also initialize GitPython with a *bare* repository.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [2-test_init_repo_object]
    :end-before: # ![2-test_init_repo_object]
    
A repo object provides high-level access to your data, it allows you to create and delete heads, tags and remotes and access the configuration of the repository.
    
.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [3-test_init_repo_object]
    :end-before: # ![3-test_init_repo_object]

Query the active branch, query untracked files or whether the repository data has been modified.
    
.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [4-test_init_repo_object]
    :end-before: # ![4-test_init_repo_object]
    
Clone from existing repositories or initialize new empty ones.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [5-test_init_repo_object]
    :end-before: # ![5-test_init_repo_object]
    
Archive the repository contents to a tar file.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [6-test_init_repo_object]
    :end-before: # ![6-test_init_repo_object]

Advanced Repo Usage
===================

And of course, there is much more you can do with this type, most of the following will be explained in greater detail in specific tutorials. Don't worry if you don't understand some of these examples right away, as they may require a thorough understanding of gits inner workings.

Query relevant repository paths ... 

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [7-test_init_repo_object]
    :end-before: # ![7-test_init_repo_object]

:class:`Heads <git.refs.head.Head>` Heads are branches in git-speak. :class:`References <git.refs.reference.Reference>` are pointers to a specific commit or to other references. Heads and :class:`Tags <git.refs.tag.TagReference>` are a kind of references. GitPython allows you to query them rather intuitively.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [8-test_init_repo_object]
    :end-before: # ![8-test_init_repo_object]

You can also create new heads ...

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [9-test_init_repo_object]
    :end-before: # ![9-test_init_repo_object]

... and tags ... 

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [10-test_init_repo_object]
    :end-before: # ![10-test_init_repo_object]

You can traverse down to :class:`git objects <git.objects.base.Object>` through references and other objects. Some objects like :class:`commits <git.objects.commit.Commit>` have additional meta-data to query.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [11-test_init_repo_object]
    :end-before: # ![11-test_init_repo_object]

:class:`Remotes <git.remote.Remote>` allow to handle fetch, pull and push operations, while providing optional real-time progress information to :class:`progress delegates <git.util.RemoteProgress>`.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [12-test_init_repo_object]
    :end-before: # ![12-test_init_repo_object]

The :class:`index <git.index.base.IndexFile>` is also called stage in git-speak. It is used to prepare new commits, and can be used to keep results of merge operations. Our index implementation allows to stream date into the index, which is useful for bare repositories that do not have a working tree.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [13-test_init_repo_object]
    :end-before: # ![13-test_init_repo_object]

:class:`Submodules <git.objects.submodule.Submodule>` represent all aspects of git submodules, which allows you query all of their related information, and manipulate in various ways.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [14-test_init_repo_object]
    :end-before: # ![14-test_init_repo_object]

    
Examining References
********************

:class:`References <git.refs.reference.Reference>` are the tips of your commit graph from which you can easily examine the history of your project.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [1-test_references_and_objects]
    :end-before: # ![1-test_references_and_objects]
    
:class:`Tags <git.refs.tag.TagReference>` are (usually immutable) references to a commit and/or a tag object.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [2-test_references_and_objects]
    :end-before: # ![2-test_references_and_objects]
    
A :class:`symbolic reference <git.refs.symbolic.SymbolicReference>` is a special case of a reference as it points to another reference instead of a commit.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [3-test_references_and_objects]
    :end-before: # ![3-test_references_and_objects]
    
Access the :class:`reflog <git.refs.log.RefLog>` easily.
    
.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [4-test_references_and_objects]
    :end-before: # ![4-test_references_and_objects]
    
Modifying References
********************
You can easily create and delete :class:`reference types <git.refs.reference.Reference>` or modify where they point to.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [5-test_references_and_objects]
    :end-before: # ![5-test_references_and_objects]

Create or delete :class:`tags <git.refs.tag.TagReference>` the same way except you may not change them afterwards.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [6-test_references_and_objects]
    :end-before: # ![6-test_references_and_objects]
    
Change the :class:`symbolic reference <git.refs.symbolic.SymbolicReference>` to switch branches cheaply (without adjusting the index or the working tree).

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [7-test_references_and_objects]
    :end-before: # ![7-test_references_and_objects]

Understanding Objects
*********************
An Object is anything storable in git's object database. Objects contain information about their type, their uncompressed size as well as the actual data. Each object is uniquely identified by a binary SHA1 hash, being 20 bytes in size, or 40 bytes in hexadecimal notation.

Git only knows 4 distinct object types being :class:`Blobs <git.objects.blob.Blob>`, :class:`Trees <git.objects.tree.Tree>`, :class:`Commits <git.objects.commit.Commit>` and :class:`Tags <git.objects.tag.TagObject>`.

In GitPython, all objects can be accessed through their common base, can be compared and hashed. They are usually not instantiated directly, but through references or specialized repository functions.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [8-test_references_and_objects]
    :end-before: # ![8-test_references_and_objects]
    
Common fields are ... 

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [9-test_references_and_objects]
    :end-before: # ![9-test_references_and_objects]
    
:class:`Index objects <git.objects.base.IndexObject>` are objects that can be put into git's index. These objects are trees, blobs and submodules which additionally know about their path in the file system as well as their mode.
    
.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [10-test_references_and_objects]
    :end-before: # ![10-test_references_and_objects]
    
Access :class:`blob <git.objects.blob.Blob>` data (or any object data) using streams.
    
.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [11-test_references_and_objects]
    :end-before: # ![11-test_references_and_objects]
    
    
The Commit object
*****************

:class:`Commit <git.objects.commit.Commit>` objects contain information about a specific commit. Obtain commits using  references as done in `Examining References`_ or as follows.

Obtain commits at the specified revision

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [12-test_references_and_objects]
    :end-before: # ![12-test_references_and_objects]    

Iterate 50 commits, and if you need paging, you can specify a number of commits to skip.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [13-test_references_and_objects]
    :end-before: # ![13-test_references_and_objects]    

A commit object carries all sorts of meta-data

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [14-test_references_and_objects]
    :end-before: # ![14-test_references_and_objects]    

Note: date time is represented in a ``seconds since epoch`` format. Conversion to human readable form can be accomplished with the various `time module <http://docs.python.org/library/time.html>`_ methods.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [15-test_references_and_objects]
    :end-before: # ![15-test_references_and_objects]    

You can traverse a commit's ancestry by chaining calls to ``parents``

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [16-test_references_and_objects]
    :end-before: # ![16-test_references_and_objects]        

The above corresponds to ``master^^^`` or ``master~3`` in git parlance.

The Tree object
***************

A :class:`tree <git.objects.tree.Tree>` records pointers to the contents of a directory. Let's say you want the root tree of the latest commit on the master branch

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [17-test_references_and_objects]
    :end-before: # ![17-test_references_and_objects]            

Once you have a tree, you can get its contents

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [18-test_references_and_objects]
    :end-before: # ![18-test_references_and_objects]            

It is useful to know that a tree behaves like a list with the ability to query entries by name

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [19-test_references_and_objects]
    :end-before: # ![19-test_references_and_objects]            

There is a convenience method that allows you to get a named sub-object from a tree with a syntax similar to how paths are written in a posix system

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [20-test_references_and_objects]
    :end-before: # ![20-test_references_and_objects]                

You can also get a commit's root tree directly from the repository

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [21-test_references_and_objects]
    :end-before: # ![21-test_references_and_objects]    
    
As trees allow direct access to their intermediate child entries only, use the traverse method to obtain an iterator to retrieve entries recursively

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [22-test_references_and_objects]
    :end-before: # ![22-test_references_and_objects]        
    
.. note:: If trees return Submodule objects, they will assume that they exist at the current head's commit. The tree it originated from may be rooted at another commit though, that it doesn't know. That is why the caller would have to set the submodule's owning or parent commit using the ``set_parent_commit(my_commit)`` method.
    
The Index Object
****************
The git index is the stage containing changes to be written with the next commit or where merges finally have to take place. You may freely access and manipulate this information using the :class:`IndexFile <git.index.base.IndexFile>` object.
Modify the index with ease
    
.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [23-test_references_and_objects]
    :end-before: # ![23-test_references_and_objects]        
    
Create new indices from other trees or as result of a merge. Write that result to a new index file for later inspection.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [24-test_references_and_objects]
    :end-before: # ![24-test_references_and_objects]        
    
Handling Remotes
****************

:class:`Remotes <git.remote.Remote>` are used as alias for a foreign repository to ease pushing to and fetching from them

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [25-test_references_and_objects]
    :end-before: # ![25-test_references_and_objects]            

You can easily access configuration information for a remote by accessing options as if they where attributes. The modification of remote configuration is more explicit though.
    
.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [26-test_references_and_objects]
    :end-before: # ![26-test_references_and_objects]

You can also specify per-call custom environments using a new context manager on the Git command, e.g. for using a specific SSH key. The following example works with `git` starting at *v2.3*::

    ssh_cmd = 'ssh -i id_deployment_key'
    with repo.git.custom_environment(GIT_SSH_COMMAND=ssh_cmd):
        repo.remotes.origin.fetch()

This one sets a custom script to be executed in place of `ssh`, and can be used in `git` prior to *v2.3*::

    ssh_executable = os.path.join(rw_dir, 'my_ssh_executable.sh')
    with repo.git.custom_environment(GIT_SSH=ssh_executable):
        repo.remotes.origin.fetch()

Here's an example executable that can be used in place of the `ssh_executable` above::

    #!/bin/sh
    ID_RSA=/var/lib/openshift/5562b947ecdd5ce939000038/app-deployments/id_rsa
    exec /usr/bin/ssh -o StrictHostKeyChecking=no -i $ID_RSA "$@"

Please note that the script must be executable (i.e. `chomd +x script.sh`). `StrictHostKeyChecking=no` is used to avoid prompts asking to save the hosts key to `~/.ssh/known_hosts`, which happens in case you run this as daemon.

You might also have a look at `Git.update_environment(...)` in case you want to setup a changed environment more permanently.
    
Submodule Handling
******************
:class:`Submodules <git.objects.submodule.base.Submodule>` can be conveniently handled using the methods provided by GitPython, and as an added benefit, GitPython provides functionality which behave smarter and less error prone than its original c-git implementation, that is GitPython tries hard to keep your repository consistent when updating submodules recursively or adjusting the existing configuration.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [1-test_submodules]
    :end-before: # ![1-test_submodules]                

In addition to the query functionality, you can move the submodule's repository to a different path <``move(...)``>, write its configuration <``config_writer().set_value(...).release()``>, update its working tree <``update(...)``>, and remove or add them <``remove(...)``, ``add(...)``>.

If you obtained your submodule object by traversing a tree object which is not rooted at the head's commit, you have to inform the submodule about its actual commit to retrieve the data from by using the ``set_parent_commit(...)`` method.

The special :class:`RootModule <git.objects.submodule.root.RootModule>` type allows you to treat your master repository as root of a hierarchy of submodules, which allows very convenient submodule handling. Its ``update(...)`` method is reimplemented to provide an advanced way of updating submodules as they change their values over time. The update method will track changes and make sure your working tree and submodule checkouts stay consistent, which is very useful in case submodules get deleted or added to name just two of the handled cases.

Additionally, GitPython adds functionality to track a specific branch, instead of just a commit. Supported by customized update methods, you are able to automatically update submodules to the latest revision available in the remote repository, as well as to keep track of changes and movements of these submodules. To use it, set the name of the branch you want to track to the ``submodule.$name.branch`` option of the *.gitmodules*  file, and use GitPython update methods on the resulting repository with the ``to_latest_revision`` parameter turned on. In the latter case, the sha of your submodule will be ignored, instead a local tracking branch will be updated to the respective remote branch automatically, provided there are no local changes. The resulting behaviour is much like the one of svn::externals, which can be useful in times. 

Obtaining Diff Information
**************************

Diffs can generally be obtained by subclasses of :class:`Diffable <git.diff.Diffable>` as they provide the ``diff`` method. This operation yields a :class:`DiffIndex <git.diff.DiffIndex>` allowing you to easily access diff information about paths.

Diffs can be made between the Index and Trees, Index and the working tree, trees and trees as well as trees and the working copy. If commits are involved, their tree will be used implicitly.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [27-test_references_and_objects]
    :end-before: # ![27-test_references_and_objects]                

The item returned is a DiffIndex which is essentially a list of Diff objects. It provides additional filtering to ease finding what you might be looking for.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [28-test_references_and_objects]
    :end-before: # ![28-test_references_and_objects]

Use the diff framework if you want to implement git-status like functionality.

* A diff between the index and the commit's tree your HEAD points to
 
 * use ``repo.index.diff(repo.head.commit)``
  
* A diff between the index and the working tree
 
 * use ``repo.index.diff(None)``
  
* A list of untracked files
 
 * use ``repo.untracked_files``

Switching Branches
******************
To switch between branches similar to ``git checkout``, you effectively need to point your HEAD symbolic reference to the new branch and reset your index and working copy to match. A simple manual way to do it is the following one

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [29-test_references_and_objects]
    :end-before: # ![29-test_references_and_objects]
    
The previous approach would brutally overwrite the user's changes in the working copy and index though and is less sophisticated than a ``git-checkout``. The latter will generally prevent you from destroying your work. Use the safer approach as follows.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [30-test_references_and_objects]
    :end-before: # ![30-test_references_and_objects]

Initializing a repository
*************************

In this example, we will initialize an empty repository, add an empty file to the index, and commit the change.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: def test_add_file_and_commit
    :end-before: # ![test_add_file_and_commit]

Please have a look at the individual methods as they usually support a vast amount of arguments to customize their behavior.

Using git directly
******************
In case you are missing functionality as it has not been wrapped, you may conveniently use the :class:`git <git.cmd.Git>` command directly. It is owned by each repository instance.

.. literalinclude:: ../../git/test/test_docs.py
    :language: python
    :start-after: # [31-test_references_and_objects]
    :end-before: # ![31-test_references_and_objects]
    
The return value will by default be a string of the standard output channel produced by the command.

Keyword arguments translate to short and long keyword arguments on the command-line.
The special notion ``git.command(flag=True)`` will create a flag without value like ``command --flag``.

If ``None`` is found in the arguments, it will be dropped silently. Lists and tuples passed as arguments will be unpacked recursively to individual arguments. Objects are converted to strings using the ``str(...)`` function.


Object Databases
****************
:class:`git.Repo <git.repo.base.Repo>` instances are powered by its object database instance which will be used when extracting any data, or when writing new objects.

The type of the database determines certain performance characteristics, such as the quantity of objects that can be read per second, the resource usage when reading large data files, as well as the average memory footprint of your application.

GitDB
=====
The GitDB is a pure-python implementation of the git object database. It is the default database to use in GitPython 0.3. Its uses less memory when handling huge files, but will be 2 to 5 times slower when extracting large quantities small of objects from densely packed repositories::
    
    repo = Repo("path/to/repo", odbt=GitDB)


GitCmdObjectDB
==============
The git command database uses persistent git-cat-file instances to read repository information. These operate very fast under all conditions, but will consume additional memory for the process itself. When extracting large files, memory usage will be much higher than the one of the ``GitDB``::
    
    repo = Repo("path/to/repo", odbt=GitCmdObjectDB)

Git Command Debugging and Customization
***************************************

Using environment variables, you can further adjust the behaviour of the git command.

* **GIT_PYTHON_TRACE**

 * If set to non-0, all executed git commands will be shown as they happen
 * If set to *full*, the executed git command _and_ its entire output on stdout and stderr will be shown as they happen

 **NOTE**: All logging is outputted using a Python logger, so make sure your program is configured to show INFO-level messages.  If this is not the case, try adding the following to your program::
 
    import logging
    logging.basicConfig(level=logging.INFO)
 
* **GIT_PYTHON_GIT_EXECUTABLE**

 * If set, it should contain the full path to the git executable, e.g. *c:\\Program Files (x86)\\Git\\bin\\git.exe* on windows or */usr/bin/git* on linux.

And even more ...
*****************

There is more functionality in there, like the ability to archive repositories, get stats and logs, blame, and probably a few other things that were not mentioned here.

Check the unit tests for an in-depth introduction on how each function is supposed to be used.

