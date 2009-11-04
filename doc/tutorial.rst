.. _tutorial_toplevel:

==================
GitPython Tutorial
==================

GitPython provides object model access to your git repository. This tutorial is 
composed of multiple sections, each of which explain a real-life usecase.

Initialize a Repo object
************************

The first step is to create a ``Repo`` object to represent your repository.

    >>> from git import *
    >>> repo = Repo("/Users/mtrier/Development/git-python")

In the above example, the directory ``/Users/mtrier/Development/git-python``
is my working repository and contains the ``.git`` directory. You can also
initialize GitPython with a bare repository.

    >>> repo = Repo.create("/var/git/git-python.git")

Examining References
********************

References are the tips of your commit graph from which you can easily examine 
the history of your project.

    >>> heads = repo.heads
    >>> master = heads.master		# lists can be accessed by name for convenience
    >>> master.commit				# the commit pointed to by head called master
    >>> master.rename("new_name")	# rename individual heads or
    
Tags are (usually immutable) references to a commit and/or a tag object.

	>>> tags = repo.tags
	>>> tagref = tags[0]
	>>>	tagref.tag			# tags may have tag objects carrying additional information
	>>> tagref.commit		# but they always point to commits
	>>> repo.delete_tag(tagref)		# delete or
	>>> repo.create_tag("my_tag")	# create tags using the repo
	
A symbolic reference is a special case of a reference as it points to another
reference instead of a commit

Modifying References
********************
You can easily create and delete reference types or modify where they point to.

	>>> repo.delete_head('master')	
	>>> master = repo.create_head('master')
	>>> master.commit = 'HEAD~10'		# set another commit without changing index or working tree	

Create or delete tags the same way except you may not change them afterwards

	>>> new_tag = repo.create_tag('my_tag', 'my message')
	>>> repo.delete_tag(new_tag)
	
Change the symbolic reference to switch branches cheaply ( without adjusting the index
or the working copy )

	>>> new_branch = repo.create_head('new_branch')
	>>> repo.head.reference = new_branch

Understanding Objects
*********************
An Object is anything storable in gits object database. Objects contain information
about their type, their uncompressed size as well as their data. Each object is
uniquely identified by a SHA1 hash, being 40 hexadecimal characters in size. 

Git only knows 4 distinct object types being Blobs, Trees, Commits and Tags.

In Git-Pyhton, all objects can be accessed through their common base, compared 
and hashed, as shown in the following example.

	>>> hc = repo.head.commit
	>>> hct = hc.tree
	>>> hc != hct
	>>> hc != repo.tags[0]
	>>> hc == repo.head.reference.commit
	
Basic fields are

	>>> hct.type
	'tree'
	>>> hct.size
	166
	>>> hct.sha
	'a95eeb2a7082212c197cabbf2539185ec74ed0e8'
	>>> hct.data		# returns string with pure uncompressed data
	'...' 
	>>> len(hct.data) == hct.size
	
Index Objects are objects that can be put into gits index. These objects are trees
and blobs which additionally know about their path in the filesystem as well as their
mode.

	>>> hct.path			# root tree has no path
	''
	>>> hct.trees[0].path	# the first subdirectory has one though
	'dir'
	>>> htc.mode			# trees have mode 0
	0
	>>> '%o' % htc.blobs[0].mode	# blobs have a specific mode though comparable to a standard linux fs
	100644
	
Access blob data (or any object data) directly or using streams.
	>>> htc.data			# binary tree data
	>>> htc.blobs[0].data_stream				# stream object to read data from
	>>> htc.blobs[0].stream_data(my_stream)	# write data to given stream
	
	
The Commit object
*****************

Commit objects contain information about a specific commit. Obtain commits using 
references as done in 'Examining References' or as follows

Obtain commits at the specified revision:

    >>> repo.commit('master')
    >>> repo.commit('v0.1')
    >>> repo.commit('HEAD~10')

Iterate 100 commits

    >>> repo.iter_commits('master', max_count=100)

If you need paging, you can specify a number of commits to skip.

    >>> repo.iter_commits('master', max_count=10, skip=20)

The above will return commits 21-30 from the commit list.

    >>> headcommit = repo.headcommit.commit 

    >>> headcommit.sha
    '207c0c4418115df0d30820ab1a9acd2ea4bf4431'

    >>> headcommit.parents
    [<git.Commit "a91c45eee0b41bf3cdaad3418ca3850664c4a4b4">]

    >>> headcommit.tree
    <git.Tree "563413aedbeda425d8d9dcbb744247d0c3e8a0ac">

    >>> headcommit.author
    <git.Actor "Michael Trier <mtrier@gmail.com>">

    >>> headcommit.authored_date		# seconds since epoch
    1256291446

    >>> headcommit.committer
    <git.Actor "Michael Trier <mtrier@gmail.com>">

    >>> headcommit.committed_date
    1256291446

    >>> headcommit.message
    'cleaned up a lot of test information. Fixed escaping so it works with
    subprocess.'

Note: date time is represented in a `seconds since epock`_ format.  Conversion to
human readable form can be accomplished with the various time module methods.

    >>> import time
    >>> time.asctime(time.gmtime(headcommit.committed_date))
    'Wed May 7 05:56:02 2008'

    >>> time.strftime("%a, %d %b %Y %H:%M", time.gmtime(headcommit.committed_date))
    'Wed, 7 May 2008 05:56'

.. _struct_time: http://docs.python.org/library/time.html

You can traverse a commit's ancestry by chaining calls to ``parents``.

    >>> headcommit.parents[0].parents[0].parents[0]

The above corresponds to ``master^^^`` or ``master~3`` in git parlance.

The Tree object
***************

A tree records pointers to the contents of a directory. Let's say you want
the root tree of the latest commit on the master branch.

    >>> tree = repo.heads.master.commit.tree
    <git.Tree "a006b5b1a8115185a228b7514cdcd46fed90dc92">

    >>> tree.sha
    'a006b5b1a8115185a228b7514cdcd46fed90dc92'

Once you have a tree, you can get the contents.

    >>> tree.trees			# trees are subdirectories
    [<git.Tree "f7eb5df2e465ab621b1db3f5714850d6732cfed2">]
    
    >>> tree.blobs			# blobs are files
    [<git.Blob "a871e79d59cf8488cac4af0c8f990b7a989e2b53">,
	<git.Blob "3594e94c04db171e2767224db355f514b13715c5">,
	<git.Blob "e79b05161e4836e5fbf197aeb52515753e8d6ab6">,
	<git.Blob "94954abda49de8615a048f8d2e64b5de848e27a1">]

Its useful to know that a tree behaves like a list with the ability to 
query entries by name.

    >>> tree[0] == tree['dir']
    <git.Tree "f7eb5df2e465ab621b1db3f5714850d6732cfed2">
    >>> for entry in tree: do_something(entry)

    >>> contents.name
    'test'

    >>> contents.mode
    '040000'

There is a convenience method that allows you to get a named sub-object
from a tree with a syntax similar to how paths are written in an unix
system.

    >>> tree/"lib"
    <git.Tree "c1c7214dde86f76bc3e18806ac1f47c38b2b7a30">

You can also get a tree directly from the repository if you know its name.

    >>> repo.tree()
    <git.Tree "master">

    >>> repo.tree("c1c7214dde86f76bc3e18806ac1f47c38b2b7a30")
    <git.Tree "c1c7214dde86f76bc3e18806ac1f47c38b2b7a30">

The Blob object
***************

A blob represents a file. Trees often contain blobs.

    >>> blob = tree['urls.py']
    <git.Blob "b19574431a073333ea09346eafd64e7b1908ef49">

A blob has certain attributes.

    >>> blob.name
    'urls.py'

    >>> blob.mode
    '100644'

    >>> blob.mime_type
    'text/x-python'

    >>> blob.size
    415

You can get the data of a blob as a string.

    >>> blob.data
    "from django.conf.urls.defaults import *\nfrom django.conf..."

You can also get a blob directly from the repo if you know its name.

    >>> repo.blob("b19574431a073333ea09346eafd64e7b1908ef49")
    <git.Blob "b19574431a073333ea09346eafd64e7b1908ef49">
    
Handling Remotes
****************

Obtaining Diff Information
**************************

Switching Branches
******************

What Else?
**********

There is more stuff in there, like the ability to tar or gzip repos, stats,
log, blame, and probably a few other things.  Additionally calls to the git
instance are handled through a ``__getattr__`` construct, which makes
available any git commands directly, with a nice conversion of Python dicts
to command line parameters.

Check the unit tests, they're pretty exhaustive.
