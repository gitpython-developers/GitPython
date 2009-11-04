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
    >>> repo.delete_head(master)	# delete them or
    >>> repo.create_head('master')	# create them
    
Tags are (usually immutable) references to a commit and/or a tag object.

	>>> tags = repo.tags
	>>> tagref = tags[0]
	>>>	tagref.tag			# tags may have tag objects carrying additional information
	>>> tagref.commit		# but they always point to commits
	>>> repo.delete_tag(tagref)		# delete or
	>>> repo.create_tag("my_tag")	# create tags using the repo

Understanding Objects
*********************
An Object is anything storable in gits object database. Objects contain information
about their type, their uncompressed size as well as their data. Each object is
uniquely identified by a SHA1 hash, being 40 hexadecimal characters in size. 

Git only knows 4 distinct object types being Blobs, Trees, Commits and Tags.

In Git-Pyhton, all objects can be accessed through their common base, compared 
and hashed, as shown in the following example.

	>>> 
	
Index Objects are objects that can be put into gits index. These objects are trees
and blobs which additionally know about their path in the filesystem as well as their
mode.

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

    >>> tree = repo.commits()[0].tree
    <git.Tree "a006b5b1a8115185a228b7514cdcd46fed90dc92">

    >>> tree.id
    'a006b5b1a8115185a228b7514cdcd46fed90dc92'

Once you have a tree, you can get the contents.

    >>> contents = tree.values()
    [<git.Blob "6a91a439ea968bf2f5ce8bb1cd8ddf5bf2cad6c7">,
     <git.Blob "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391">,
     <git.Tree "eaa0090ec96b054e425603480519e7cf587adfc3">,
     <git.Blob "980e72ae16b5378009ba5dfd6772b59fe7ccd2df">]

The tree is implements a dictionary protocol so it can be used and acts just
like a dictionary with some additional properties.

    >>> tree.items()
    [('lib', <git.Tree "310ebc9a0904531438bdde831fd6a27c6b6be58e">),
     ('LICENSE', <git.Blob "6797c1421052efe2ded9efdbb498b37aeae16415">),
     ('doc', <git.Tree "a58386dd101f6eb7f33499317e5508726dfd5e4f">),
     ('MANIFEST.in', <git.Blob "7da4e346bb0a682e99312c48a1f452796d3fb988">),
     ('.gitignore', <git.Blob "6870991011cc8d9853a7a8a6f02061512c6a8190">),
     ('test', <git.Tree "c6f6ee37d328987bc6fb47a33fed16c7886df857">),
     ('VERSION', <git.Blob "9faa1b7a7339db85692f91ad4b922554624a3ef7">),
     ('AUTHORS', <git.Blob "9f649ef5448f9666d78356a2f66ba07c5fb27229">),
     ('README', <git.Blob "9643dcf549f34fbd09503d4c941a5d04157570fe">),
     ('ez_setup.py', <git.Blob "3031ad0d119bd5010648cf8c038e2bbe21969ecb">),
     ('setup.py', <git.Blob "271074302aee04eb0394a4706c74f0c2eb504746">),
     ('CHANGES', <git.Blob "0d236f3d9f20d5e5db86daefe1e3ba1ce68e3a97">)]

This tree contains three ``Blob`` objects and one ``Tree`` object. The trees
are subdirectories and the blobs are files. Trees below the root have
additional attributes.

    >>> contents = tree["lib"]
    <git.Tree "c1c7214dde86f76bc3e18806ac1f47c38b2b7a3">

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

What Else?
**********

There is more stuff in there, like the ability to tar or gzip repos, stats,
log, blame, and probably a few other things.  Additionally calls to the git
instance are handled through a ``__getattr__`` construct, which makes
available any git commands directly, with a nice conversion of Python dicts
to command line parameters.

Check the unit tests, they're pretty exhaustive.
