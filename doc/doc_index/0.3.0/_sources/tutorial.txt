.. _tutorial_toplevel:

.. highlight:: python

.. _tutorial-label:

==================
GitPython Tutorial
==================

GitPython provides object model access to your git repository. This tutorial is  composed of multiple sections, each of which explains a real-life usecase.

Initialize a Repo object
************************

The first step is to create a ``Repo`` object to represent your repository::

    from git import *
    repo = Repo("/Users/mtrier/Development/git-python")
    assert repo.bare == False

In the above example, the directory ``/Users/mtrier/Development/git-python`` is my working repository and contains the ``.git`` directory. You can also initialize GitPython with a *bare* repository::

    repo = Repo.init("/var/git/git-python.git", bare=True)
    assert repo.bare == True
    
A repo object provides high-level access to your data, it allows you to create and delete heads, tags and remotes and access the configuration of the  repository::
    
    repo.config_reader()        # get a config reader for read-only access
    repo.config_writer()        # get a config writer to change configuration 

Query the active branch, query untracked files or whether the repository data  has been modified::
    
    repo.is_dirty()
    False
    repo.untracked_files
    ['my_untracked_file']
    
Clone from existing repositories or initialize new empty ones::

    cloned_repo = repo.clone("to/this/path")
    new_repo = repo.init("path/for/new/repo")
    
Archive the repository contents to a tar file::

    repo.archive(open("repo.tar",'w'))
    
    
Object Databases
****************
``Repo`` instances are powered by its object database instance which will be used when extracting any data, or when writing new objects.

The type of the database determines certain performance characteristics, such as the quantity of objects that can be read per second, the resource usage when reading large data files, as well as the average memory footprint of your application.

GitDB
=====
The GitDB is a pure-python implementation of the git object database. It is the default database to use in GitPython 0.3. Its uses less memory when handling huge files, but will be 2 to 5 times slower when extracting large quantities small of objects from densely packed repositories::
    
    repo = Repo("path/to/repo", odbt=GitDB)

GitCmdObjectDB
==============
The git command database uses persistent git-cat-file instances to read repository information. These operate very fast under all conditions, but will consume additional memory for the process itself. When extracting large files, memory usage will be much higher than the one of the ``GitDB``::
    
    repo = Repo("path/to/repo", odbt=GitCmdObjectDB)
    
Examining References
********************

References are the tips of your commit graph from which you can easily examine  the history of your project::

    heads = repo.heads
    master = heads.master       # lists can be accessed by name for convenience
    master.commit               # the commit pointed to by head called master
    master.rename("new_name")   # rename heads
    
Tags are (usually immutable) references to a commit and/or a tag object::

    tags = repo.tags
    tagref = tags[0]
    tagref.tag                  # tags may have tag objects carrying additional information
    tagref.commit               # but they always point to commits
    repo.delete_tag(tagref)     # delete or
    repo.create_tag("my_tag")   # create tags using the repo for convenience
    
A symbolic reference is a special case of a reference as it points to another reference instead of a commit::

    head = repo.head            # the head points to the active branch/ref
    master = head.reference     # retrieve the reference the head points to
    master.commit               # from here you use it as any other reference

Modifying References
********************
You can easily create and delete reference types or modify where they point to::

    repo.delete_head('master')           # delete an existing head
    master = repo.create_head('master')  # create a new one
    master.commit = 'HEAD~10'            # set branch to another commit without changing index or working tree 

Create or delete tags the same way except you may not change them afterwards::

    new_tag = repo.create_tag('my_tag', 'my message')
    repo.delete_tag(new_tag)
    
Change the symbolic reference to switch branches cheaply ( without adjusting the index or the working copy )::

    new_branch = repo.create_head('new_branch')
    repo.head.reference = new_branch

Understanding Objects
*********************
An Object is anything storable in git's object database. Objects contain information about their type, their uncompressed size as well as the actual data. Each object is uniquely identified by a binary SHA1 hash, being 20 bytes in size.

Git only knows 4 distinct object types being Blobs, Trees, Commits and Tags.

In Git-Python, all objects can be accessed through their common base, compared  and hashed. They are usually not instantiated directly, but through references or specialized repository functions::

    hc = repo.head.commit
    hct = hc.tree
    hc != hct
    hc != repo.tags[0]
    hc == repo.head.reference.commit
    
Common fields are::

    hct.type
    'tree'
    hct.size
    166
    hct.hexsha
    'a95eeb2a7082212c197cabbf2539185ec74ed0e8'
    hct.binsha
    'binary 20 byte sha1'
    
Index Objects are objects that can be put into git's index. These objects are trees, blobs and submodules which additionally know about their path in the filesystem as well as their mode::
    
    hct.path            # root tree has no path
    ''
    hct.trees[0].path   # the first subdirectory has one though
    'dir'
    htc.mode            # trees have the mode of a linux directory
    040000
    '%o' % htc.blobs[0].mode    # blobs have a specific mode though comparable to a standard linux fs
    100644
    
Access blob data (or any object data) directly or using streams::
    
    htc.blobs[0].data_stream.read()      # stream object to read data from
    htc.blobs[0].stream_data(open("blob_data", "w")) # write data to given stream
    
    
The Commit object
*****************

Commit objects contain information about a specific commit. Obtain commits using  references as done in `Examining References`_ or as follows.

Obtain commits at the specified revision::

    repo.commit('master')
    repo.commit('v0.1')
    repo.commit('HEAD~10')

Iterate 100 commits::

    repo.iter_commits('master', max_count=100)

If you need paging, you can specify a number of commits to skip::

    repo.iter_commits('master', max_count=10, skip=20)

The above will return commits 21-30 from the commit list.::

    headcommit = repo.head.commit 

    headcommit.hexsha
    '207c0c4418115df0d30820ab1a9acd2ea4bf4431'

    headcommit.parents
    (<git.Commit "a91c45eee0b41bf3cdaad3418ca3850664c4a4b4">,)

    headcommit.tree
    <git.Tree "563413aedbeda425d8d9dcbb744247d0c3e8a0ac">

    headcommit.author
    <git.Actor "Michael Trier <mtrier@gmail.com>">

    headcommit.authored_date        # seconds since epoch
    1256291446

    headcommit.committer
    <git.Actor "Michael Trier <mtrier@gmail.com>">

    headcommit.committed_date
    1256291446

    headcommit.message
    'cleaned up a lot of test information. Fixed escaping so it works with
    subprocess.'

Note: date time is represented in a ``seconds since epoch`` format. Conversion to human readable form can be accomplished with the various `time module <http://docs.python.org/library/time.html>`_ methods::

    import time
    time.asctime(time.gmtime(headcommit.committed_date))
    'Wed May 7 05:56:02 2008'

    time.strftime("%a, %d %b %Y %H:%M", time.gmtime(headcommit.committed_date))
    'Wed, 7 May 2008 05:56'

You can traverse a commit's ancestry by chaining calls to ``parents``::

    headcommit.parents[0].parents[0].parents[0]

The above corresponds to ``master^^^`` or ``master~3`` in git parlance.

The Tree object
***************

A tree records pointers to the contents of a directory. Let's say you want the root tree of the latest commit on the master branch::

    tree = repo.heads.master.commit.tree
    <git.Tree "a006b5b1a8115185a228b7514cdcd46fed90dc92">

    tree.hexsha
    'a006b5b1a8115185a228b7514cdcd46fed90dc92'

Once you have a tree, you can get the contents::

    tree.trees          # trees are subdirectories
    [<git.Tree "f7eb5df2e465ab621b1db3f5714850d6732cfed2">]
    
    tree.blobs          # blobs are files
    [<git.Blob "a871e79d59cf8488cac4af0c8f990b7a989e2b53">,
    <git.Blob "3594e94c04db171e2767224db355f514b13715c5">,
    <git.Blob "e79b05161e4836e5fbf197aeb52515753e8d6ab6">,
    <git.Blob "94954abda49de8615a048f8d2e64b5de848e27a1">]

Its useful to know that a tree behaves like a list with the ability to  query entries by name::

    tree[0] == tree['dir']			# access by index and by sub-path
    <git.Tree "f7eb5df2e465ab621b1db3f5714850d6732cfed2">
    for entry in tree: do_something_with(entry)

    blob = tree[0][0]
    blob.name
    'file'
    blob.path
    'dir/file'
    blob.abspath
    '/Users/mtrier/Development/git-python/dir/file'
    >>>tree['dir/file'].binsha == blob.binsha

There is a convenience method that allows you to get a named sub-object from a tree with a syntax similar to how paths are written in an unix system::

    tree/"lib"
    <git.Tree "c1c7214dde86f76bc3e18806ac1f47c38b2b7a30">
    tree/"dir/file" == blob

You can also get a tree directly from the repository if you know its name::

    repo.tree()
    <git.Tree "master">

    repo.tree("c1c7214dde86f76bc3e18806ac1f47c38b2b7a30")
    <git.Tree "c1c7214dde86f76bc3e18806ac1f47c38b2b7a30">
    repo.tree('0.1.6')
    <git.Tree "6825a94104164d9f0f5632607bebd2a32a3579e5">
    
As trees only allow direct access to their direct entries, use the traverse  method to obtain an iterator to traverse entries recursively::

    tree.traverse()
    <generator object at 0x7f6598bd65a8>
    for entry in tree.traverse(): do_something_with(entry)

    
The Index Object
****************
The git index is the stage containing changes to be written with the next commit or where merges finally have to take place. You may freely access and manipulate  this information using the IndexFile Object::

    index = repo.index
    
Access objects and add/remove entries. Commit the changes::

    for stage, blob in index.iter_blobs(): do_something(...)
    # Access blob objects
    for (path, stage), entry in index.entries.iteritems: pass
    # Access the entries directly
    index.add(['my_new_file'])      # add a new file to the index
    index.remove(['dir/existing_file'])
    new_commit = index.commit("my commit message")
    
Create new indices from other trees or as result of a merge. Write that result to a new index file::

    tmp_index = Index.from_tree(repo, 'HEAD~1') # load a tree into a temporary index
    merge_index = Index.from_tree(repo, 'base', 'HEAD', 'some_branch') # merge two trees three-way
    merge_index.write("merged_index")
    
Handling Remotes
****************

Remotes are used as alias for a foreign repository to ease pushing to and fetching from them::

    test_remote = repo.create_remote('test', 'git@server:repo.git')
    repo.delete_remote(test_remote) # create and delete remotes
    origin = repo.remotes.origin    # get default remote by name
    origin.refs                     # local remote references
    o = origin.rename('new_origin') # rename remotes
    o.fetch()                       # fetch, pull and push from and to the remote
    o.pull()
    o.push()

You can easily access configuration information for a remote by accessing options  as if they where attributes::
    
    o.url
    'git@server:dummy_repo.git'
    
Change configuration for a specific remote only::
    
    o.config_writer.set("pushurl", "other_url")
    
Obtaining Diff Information
**************************

Diffs can generally be obtained by subclasses of ``Diffable`` as they provide  the ``diff`` method. This operation yields a DiffIndex allowing you to easily access diff information about paths.

Diffs can be made between the Index and Trees, Index and the working tree, trees and trees as well as trees and the working copy. If commits are involved, their tree will be used implicitly::

    hcommit = repo.head.commit
    idiff = hcommit.diff()          # diff tree against index
    tdiff = hcommit.diff('HEAD~1')  # diff tree against previous tree
    wdiff = hcommit.diff(None)      # diff tree against working tree
    
    index = repo.index
    index.diff()                    # diff index against itself yielding empty diff
    index.diff(None)                # diff index against working copy
    index.diff('HEAD')              # diff index against current HEAD tree

The item returned is a DiffIndex which is essentially a list of Diff objects. It  provides additional filtering to ease finding what you might be looking for::

    for diff_added in wdiff.iter_change_type('A'): do_something_with(diff_added)

Switching Branches
******************
To switch between branches, you effectively need to point your HEAD to the new branch head and reset your index and working copy to match. A simple manual way to do it is the following one::

    repo.head.reference = repo.heads.other_branch
    repo.head.reset(index=True, working_tree=True)
    
The previous approach would brutally overwrite the user's changes in the working copy and index though and is less sophisticated than a git-checkout for instance which generally prevents you from destroying your work. Use the safer approach as follows::

	repo.heads.master.checkout()			# checkout the branch using git-checkout
	repo.heads.other_branch.checkout()

Using git directly
******************
In case you are missing functionality as it has not been wrapped, you may conveniently use the git command directly. It is owned by each repository instance::

    git = repo.git
    git.checkout('head', b="my_new_branch")         # default command
    git.for_each_ref()                              # '-' becomes '_' when calling it
    
The return value will by default be a string of the standard output channel produced by the command.

Keyword arguments translate to short and long keyword arguments on the commandline.
The special notion ``git.command(flag=True)`` will create a flag without value like ``command --flag``.

If ``None`` is found in the arguments, it will be dropped silently. Lists and tuples  passed as arguments will be unpacked recursively to individual arguments. Objects are converted to strings using the str(...) function.

And even more ...
*****************

There is more functionality in there, like the ability to archive repositories, get stats and logs, blame, and probably a few other things that were not mentioned here.  

Check the unit tests for an in-depth introduction on how each function is supposed to be used.

