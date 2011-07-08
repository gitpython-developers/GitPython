# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Contains interfaces for basic database building blocks"""

__all__ = (	'ObjectDBR', 'ObjectDBW', 'RootPathDB', 'CompoundDB', 'CachingDB', 
			'TransportDB', 'ConfigurationMixin', 'RepositoryPathsMixin',  
			'RefSpec', 'FetchInfo', 'PushInfo', 'ReferencesMixin', 'SubmoduleDB', 
			'IndexDB', 'HighLevelRepository')


class ObjectDBR(object):
	"""Defines an interface for object database lookup.
	Objects are identified either by their 20 byte bin sha"""
	
	def __contains__(self, sha):
		return self.has_obj(sha)
	
	#{ Query Interface 
	def has_object(self, sha):
		"""
		:return: True if the object identified by the given 20 bytes
			binary sha is contained in the database"""
		raise NotImplementedError("To be implemented in subclass")
		
	def has_object_async(self, reader):
		"""Return a reader yielding information about the membership of objects
		as identified by shas
		:param reader: Reader yielding 20 byte shas.
		:return: async.Reader yielding tuples of (sha, bool) pairs which indicate
			whether the given sha exists in the database or not"""
		raise NotImplementedError("To be implemented in subclass")
		
	def info(self, sha):
		""" :return: OInfo instance
		:param sha: bytes binary sha
		:raise BadObject:"""
		raise NotImplementedError("To be implemented in subclass")
		
	def info_async(self, reader):
		"""Retrieve information of a multitude of objects asynchronously
		:param reader: Channel yielding the sha's of the objects of interest
		:return: async.Reader yielding OInfo|InvalidOInfo, in any order"""
		raise NotImplementedError("To be implemented in subclass")
		
	def stream(self, sha):
		""":return: OStream instance
		:param sha: 20 bytes binary sha
		:raise BadObject:"""
		raise NotImplementedError("To be implemented in subclass")
		
	def stream_async(self, reader):
		"""Retrieve the OStream of multiple objects
		:param reader: see ``info``
		:param max_threads: see ``ObjectDBW.store``
		:return: async.Reader yielding OStream|InvalidOStream instances in any order
		:note: depending on the system configuration, it might not be possible to 
			read all OStreams at once. Instead, read them individually using reader.read(x)
			where x is small enough."""
		raise NotImplementedError("To be implemented in subclass")
	
	def size(self):
		""":return: amount of objects in this database"""
		raise NotImplementedError()
		
	def sha_iter(self):
		"""Return iterator yielding 20 byte shas for all objects in this data base"""
		raise NotImplementedError()
		
	def partial_to_complete_sha_hex(self, partial_hexsha):
		"""
		:return: 20 byte binary sha1 from the given less-than-40 byte hexsha
		:param partial_hexsha: hexsha with less than 40 byte
		:raise AmbiguousObjectName: If multiple objects would match the given sha 
		:raies BadObject: If object was not found"""
		raise NotImplementedError()
			
	def partial_to_complete_sha(self, partial_binsha, canonical_length):
		""":return: 20 byte sha as inferred by the given partial binary sha
		:param partial_binsha: binary sha with less than 20 bytes 
		:param canonical_length: length of the corresponding canonical (hexadecimal) representation.
			It is required as binary sha's cannot display whether the original hex sha
			had an odd or even number of characters
		:raise AmbiguousObjectName: 
		:raise BadObject: """
	#} END query interface
	
	
class ObjectDBW(object):
	"""Defines an interface to create objects in the database"""
	
	#{ Edit Interface
	def set_ostream(self, stream):
		"""
		Adjusts the stream to which all data should be sent when storing new objects
		
		:param stream: if not None, the stream to use, if None the default stream
			will be used.
		:return: previously installed stream, or None if there was no override
		:raise TypeError: if the stream doesn't have the supported functionality"""
		raise NotImplementedError("To be implemented in subclass")
		
	def ostream(self):
		"""
		:return: overridden output stream this instance will write to, or None
			if it will write to the default stream"""
		raise NotImplementedError("To be implemented in subclass")
	
	def store(self, istream):
		"""
		Create a new object in the database
		:return: the input istream object with its sha set to its corresponding value
		
		:param istream: IStream compatible instance. If its sha is already set 
			to a value, the object will just be stored in the our database format, 
			in which case the input stream is expected to be in object format ( header + contents ).
		:raise IOError: if data could not be written"""
		raise NotImplementedError("To be implemented in subclass")
	
	def store_async(self, reader):
		"""
		Create multiple new objects in the database asynchronously. The method will 
		return right away, returning an output channel which receives the results as 
		they are computed.
		
		:return: Channel yielding your IStream which served as input, in any order.
			The IStreams sha will be set to the sha it received during the process, 
			or its error attribute will be set to the exception informing about the error.
			
		:param reader: async.Reader yielding IStream instances.
			The same instances will be used in the output channel as were received
			in by the Reader.
		
		:note:As some ODB implementations implement this operation atomic, they might 
			abort the whole operation if one item could not be processed. Hence check how 
			many items have actually been produced."""
		raise NotImplementedError("To be implemented in subclass")
	
	#} END edit interface
	

class RootPathDB(object):
	"""Provides basic facilities to retrieve files of interest"""
	
	def __init__(self, root_path):
		"""Initialize this instance to look for its files at the given root path
		All subsequent operations will be relative to this path
		:raise InvalidDBRoot: 
		:note: The base will not perform any accessablity checking as the base
			might not yet be accessible, but become accessible before the first 
			access."""
		try:
			super(RootPathDB, self).__init__(root_path)
		except TypeError:
			pass
		# END handle py 2.6
		
	#{ Interface
	def root_path(self):
		""":return: path at which this db operates"""
		raise NotImplementedError()
	
	def db_path(self, rela_path):
		"""
		:return: the given relative path relative to our database root, allowing 
			to pontentially access datafiles
		:param rela_path: if not None or '', the relative path will be appended 
			to the database root path. Otherwise you will obtain the database root path itself"""
		raise NotImplementedError()
	#} END interface
		

class CachingDB(object):
	"""A database which uses caches to speed-up access"""
	
	#{ Interface 
	
	def update_cache(self, force=False):
		"""
		Call this method if the underlying data changed to trigger an update
		of the internal caching structures.
		
		:param force: if True, the update must be performed. Otherwise the implementation
			may decide not to perform an update if it thinks nothing has changed.
		:return: True if an update was performed as something change indeed"""
		
	# END interface


class CompoundDB(object):
	"""A database which delegates calls to sub-databases.
	They should usually be cached and lazy-loaded"""
	
	#{ Interface
	
	def databases(self):
		""":return: tuple of database instances we use for lookups"""
		raise NotImplementedError()

	#} END interface
	
	
class IndexDB(object):
	"""A database which provides a flattened index to all objects in its currently 
	active tree."""
	@property
	def index(self):
		""":return: IndexFile compatible instance"""
		raise NotImplementedError()
	

class RefSpec(object):
	"""A refspec is a simple container which provides information about the way
	something should be fetched or pushed. It requires to use symbols to describe
	the actual objects which is done using reference names (or respective instances
	which resolve to actual reference names)."""
	__slots__ = ('source', 'destination', 'force')
	
	def __init__(self, source, destination, force=False):
		"""initalize the instance with the required values
		:param source: reference name or instance. If None, the Destination 
			is supposed to be deleted."""
		self.source = source
		self.destination = destination
		self.force = force
		if self.destination is None:
			raise ValueError("Destination must be set")
		
	def __str__(self):
		""":return: a git-style refspec"""
		s = str(self.source)
		if self.source is None:
			s = ''
		#END handle source
		d = str(self.destination)
		p = ''
		if self.force:
			p = '+'
		#END handle force
		res = "%s%s:%s" % (p, s, d)
		
	def delete_destination(self):
		return self.source is None
		
		
class RemoteProgress(object):
	"""
	Handler providing an interface to parse progress information emitted by git-push
	and git-fetch and to dispatch callbacks allowing subclasses to react to the progress.
	
	Subclasses should derive from this type.
	"""
	_num_op_codes = 7
	BEGIN, END, COUNTING, COMPRESSING, WRITING, RECEIVING, RESOLVING =  [1 << x for x in range(_num_op_codes)]
	STAGE_MASK = BEGIN|END
	OP_MASK = ~STAGE_MASK
	
	#{ Subclass Interface
	
	def line_dropped(self, line):
		"""Called whenever a line could not be understood and was therefore dropped."""
		pass
	
	def update(self, op_code, cur_count, max_count=None, message='', input=''):
		"""Called whenever the progress changes
		
		:param op_code:
			Integer allowing to be compared against Operation IDs and stage IDs.
			
			Stage IDs are BEGIN and END. BEGIN will only be set once for each Operation 
			ID as well as END. It may be that BEGIN and END are set at once in case only
			one progress message was emitted due to the speed of the operation.
			Between BEGIN and END, none of these flags will be set
			
			Operation IDs are all held within the OP_MASK. Only one Operation ID will 
			be active per call.
		:param cur_count: Current absolute count of items
			
		:param max_count:
			The maximum count of items we expect. It may be None in case there is 
			no maximum number of items or if it is (yet) unknown.
		
		:param message:
			In case of the 'WRITING' operation, it contains the amount of bytes
			transferred. It may possibly be used for other purposes as well.
		
		:param input:
			The actual input string that was used to parse the information from.
			This is usually a line from the output of git-fetch, but really
			depends on the implementation
		
		You may read the contents of the current line in self._cur_line"""
		pass
	
	def __call__(self, message, input=''):
		"""Same as update, but with a simpler interface which only provides the
		message of the operation.
		:note: This method will be called in addition to the update method. It is 
			up to you which one you implement"""
		pass
	#} END subclass interface
	
		
class PushInfo(object):
	"""A type presenting information about the result of a push operation for exactly
	one refspec

	flags				# bitflags providing more information about the result
	local_ref			# Reference pointing to the local reference that was pushed
						# It is None if the ref was deleted.
	remote_ref_string 	# path to the remote reference located on the remote side
	remote_ref 			# Remote Reference on the local side corresponding to 
						# the remote_ref_string. It can be a TagReference as well.
	old_commit_binsha 	# binary sha to commit at which the remote_ref was standing before we pushed
						# it to local_ref.commit. Will be None if an error was indicated
	summary				# summary line providing human readable english text about the push
	"""
	__slots__ = tuple()
	
	NEW_TAG, NEW_HEAD, NO_MATCH, REJECTED, REMOTE_REJECTED, REMOTE_FAILURE, DELETED, \
	FORCED_UPDATE, FAST_FORWARD, UP_TO_DATE, ERROR = [ 1 << x for x in range(11) ]
		
		
class FetchInfo(object):
	"""A type presenting information about the fetch operation on exactly one refspec
	
	The following members are defined:
	ref				# name of the reference to the changed 
					# remote head or FETCH_HEAD. Implementations can provide
					# actual class instance which convert to a respective string
	flags			# additional flags to be & with enumeration members, 
					# i.e. info.flags & info.REJECTED 
					# is 0 if ref is FETCH_HEAD
	note				# additional notes given by the fetch-pack implementation intended for the user
	old_commit_binsha# if info.flags & info.FORCED_UPDATE|info.FAST_FORWARD, 
					# field is set to the previous location of ref as binary sha or None"""
	__slots__ = tuple()
	
	NEW_TAG, NEW_HEAD, HEAD_UPTODATE, TAG_UPDATE, REJECTED, FORCED_UPDATE, \
	FAST_FORWARD, ERROR = [ 1 << x for x in range(8) ]


class TransportDB(object):
	"""A database which allows to transport objects from and to different locations
	which are specified by urls (location) and refspecs (what to transport, 
	see http://www.kernel.org/pub/software/scm/git/docs/git-fetch.html).
	
	At the beginning of a transport operation, it will be determined which objects
	have to be sent (either by this or by the other side).
	
	Afterwards a pack with the required objects is sent (or received). If there is 
	nothing to send, the pack will be empty.
	
	As refspecs involve symbolic names for references to be handled, we require
	RefParse functionality. How this is done is up to the actual implementation."""
	# The following variables need to be set by the derived class
	
	#{ Interface
	
	def fetch(self, url, refspecs, progress=None, **kwargs):
		"""Fetch the objects defined by the given refspec from the given url.
		:param url: url identifying the source of the objects. It may also be 
			a symbol from which the respective url can be resolved, like the
			name of the remote. The implementation should allow objects as input
			as well, these are assumed to resovle to a meaningful string though.
		:param refspecs: iterable of reference specifiers or RefSpec instance, 
			identifying the references to be fetch from the remote.
		:param progress: RemoteProgress derived instance which receives progress messages for user consumption or None
		:param kwargs: may be used for additional parameters that the actual implementation could 
			find useful.
		:return: List of FetchInfo compatible instances which provide information about what 
			was previously fetched, in the order of the input refspecs.
		:note: even if the operation fails, one of the returned FetchInfo instances
			may still contain errors or failures in only part of the refspecs.
		:raise: if any issue occours during the transport or if the url is not 
			supported by the protocol.
		"""
		raise NotImplementedError()
		
	def push(self, url, refspecs, progress=None, **kwargs):
		"""Transport the objects identified by the given refspec to the remote
		at the given url.
		:param url: Decribes the location which is to receive the objects
			see fetch() for more details
		:param refspecs: iterable of refspecs strings or RefSpec instances
			to identify the objects to push
		:param progress: see fetch() 
		:param kwargs: additional arguments which may be provided by the caller
			as they may be useful to the actual implementation
		:todo: what to return ?
		:raise: if any issue arises during transport or if the url cannot be handled"""
		raise NotImplementedError()
		
	@property
	def remotes(self):
		""":return: An IterableList of Remote objects allowing to access and manipulate remotes
		:note: Remote objects can also be used for the actual push or fetch operation"""
		raise NotImplementedError()
		
	def remote(self, name='origin'):
		""":return: Remote object with the given name
		:note: it does not necessarily exist, hence this is just a more convenient way
			to construct Remote objects"""
		raise NotImplementedError()
		
	#}end interface
	
			
	#{ Utility Methods
		
	def create_remote(self, name, url, **kwargs):
		"""Create a new remote with the given name pointing to the given url
		:return: Remote instance, compatible to the Remote interface"""
		return Remote.create(self, name, url, **kwargs)
		
	def delete_remote(self, remote):
		"""Delete the given remote.
		:param remote: a Remote instance"""
		return Remote.remove(self, remote)
		
	#} END utility methods


class ReferencesMixin(object):
	"""Database providing reference objects which in turn point to database objects
	like Commits or Tag(Object)s.
	
	The returned types are compatible to the interfaces of the pure python 
	reference implementation in GitDB.ref"""
	
	def resolve(self, name):
		"""Resolve the given name into a binary sha. Valid names are as defined 
		in the rev-parse documentation http://www.kernel.org/pub/software/scm/git/docs/git-rev-parse.html
		:return: binary sha matching the name
		:raise AmbiguousObjectName:
		:raise BadObject: """
		raise NotImplementedError()
		
	def resolve_object(self, name):
		"""As ``resolve()``, but returns the Objecft instance pointed to by the 
		resolved binary sha
		:return: Object instance of the correct type, e.g. shas pointing to commits
			will be represented by a Commit object"""
		raise NotImplementedError()
	
	@property
	def references(self):
		""":return: iterable list of all Reference objects representing tags, heads
		and remote references. This is the most general method to obtain any 
		references."""
		raise NotImplementedError()
		
	@property
	def heads(self):
		""":return: IterableList with HeadReference objects pointing to all
		heads in the repository."""
		raise NotImplementedError()
		
	@property
	def head(self):
		""":return: HEAD Object pointing to the current head reference"""
		raise NotImplementedError()
		
	@property
	def tags(self):
		""":return: An IterableList of TagReferences or compatible items that 
		are available in this repo"""
		raise NotImplementedError()

	#{ Utility Methods
	
	def tag(self, name):
		""":return: Tag with the given name
		:note: It does not necessarily exist, hence this is just a more convenient
			way to construct TagReference objects"""
		raise NotImplementedError()
		
	
	def commit(self, rev=None):
		"""The Commit object for the specified revision
		:param rev: revision specifier, see git-rev-parse for viable options.
		:return: Commit compatible object"""
		raise NotImplementedError()
		
	def iter_trees(self, *args, **kwargs):
		""":return: Iterator yielding Tree compatible objects
		:note: Takes all arguments known to iter_commits method"""
		raise NotImplementedError()

	def tree(self, rev=None):
		"""The Tree (compatible) object for the given treeish revision
		Examples::
	
			  repo.tree(repo.heads[0])

		:param rev: is a revision pointing to a Treeish ( being a commit or tree )
		:return: ``git.Tree``
			
		:note:
			If you need a non-root level tree, find it by iterating the root tree. Otherwise
			it cannot know about its path relative to the repository root and subsequent 
			operations might have unexpected results."""
		raise NotImplementedError()

	def iter_commits(self, rev=None, paths='', **kwargs):
		"""A list of Commit objects representing the history of a given ref/commit

		:parm rev:
			revision specifier, see git-rev-parse for viable options.
			If None, the active branch will be used.

		:parm paths:
			is an optional path or a list of paths to limit the returned commits to
			Commits that do not contain that path or the paths will not be returned.
		
		:parm kwargs:
			Arguments to be passed to git-rev-list - common ones are 
			max_count and skip

		:note: to receive only commits between two named revisions, use the 
			"revA..revB" revision specifier

		:return: iterator yielding Commit compatible instances"""
		raise NotImplementedError()

	
	#} END utility methods
		
	#{ Edit Methods
		
	def create_head(self, path, commit='HEAD', force=False, logmsg=None ):
		"""Create a new head within the repository.
		:param commit:  a resolvable name to the commit or a Commit or Reference instance the new head should point to
		:param force: if True, a head will be created even though it already exists
			Otherwise an exception will be raised.
		:param logmsg: message to append to the reference log. If None, a default message 
			will be used
		:return: newly created Head instances"""
		raise NotImplementedError()
		
	def delete_head(self, *heads):
		"""Delete the given heads
		:param heads: list of Head references that are to be deleted"""
		raise NotImplementedError()
		
	def create_tag(self, path, ref='HEAD', message=None, force=False):
		"""Create a new tag reference.
		:param path: name or path of the new tag.
		:param ref: resolvable name of the reference or commit, or Commit or Reference
			instance describing the commit the tag should point to.
		:param message: message to be attached to the tag reference. This will 
			create an actual Tag object carrying the message. Otherwise a TagReference
			will be generated.
		:param force: if True, the Tag will be created even if another tag does already
			exist at the given path. Otherwise an exception will be thrown
		:return: TagReference object """
		raise NotImplementedError()
		
	def delete_tag(self, *tags):
		"""Delete the given tag references
		:param tags: TagReferences to delete"""
		raise NotImplementedError()
		
	#}END edit methods


class RepositoryPathsMixin(object):
	"""Represents basic functionality of a full git repository. This involves an 
	optional working tree, a git directory with references and an object directory.
	
	This type collects the respective paths and verifies the provided base path 
	truly is a git repository.
	
	If the underlying type provides the config_reader() method, we can properly determine 
	whether this is a bare repository as well. Otherwise it will make an educated guess
	based on the path name."""
	#{ Subclass Interface
	def _initialize(self, path):
		"""initialize this instance with the given path. It may point to 
		any location within the repositories own data, as well as the working tree.
		
		The implementation will move up and search for traces of a git repository, 
		which is indicated by a child directory ending with .git or the 
		current path portion ending with .git.
		
		The paths made available for query are suitable for full git repositories
		only. Plain object databases need to be fed the "objects" directory path.
		
		:param path: the path to initialize the repository with
			It is a path to either the root git directory or the bare git repo::

			repo = Repo("/Users/mtrier/Development/git-python")
			repo = Repo("/Users/mtrier/Development/git-python.git")
			repo = Repo("~/Development/git-python.git")
			repo = Repo("$REPOSITORIES/Development/git-python.git")
		
		:raise InvalidDBRoot:
		"""
		raise NotImplementedError()
	#} end subclass interface
	
	#{ Object Interface
	
	def __eq__(self, rhs):
		raise NotImplementedError()
		
	def __ne__(self, rhs):
		raise NotImplementedError()
		
	def __hash__(self):
		raise NotImplementedError()

	def __repr__(self):
		raise NotImplementedError()
	
	#} END object interface
	
	#{ Interface
	
	@property
	def is_bare(self):
		""":return: True if this is a bare repository
		:note: this value is cached upon initialization"""
		raise NotImplementedError()
		
	@property
	def git_dir(self):
		""":return: path to directory containing this actual git repository (which 
		in turn provides access to objects and references"""
		raise NotImplementedError()
		
	@property
	def working_tree_dir(self):
		""":return: path to directory containing the working tree checkout of our 
		git repository.
		:raise AssertionError: If this is a bare repository"""
		raise NotImplementedError()
		
	@property
	def objects_dir(self):
		""":return: path to the repository's objects directory"""
		raise NotImplementedError()
		
	@property
	def working_dir(self):
		""":return: working directory of the git process or related tools, being 
		either the working_tree_dir if available or the git_path"""
		raise NotImplementedError()

	@property
	def description(self):
		""":return: description text associated with this repository or set the 
		description."""
		raise NotImplementedError()
	
	#} END interface
		
		
class ConfigurationMixin(object):
	"""Interface providing configuration handler instances, which provide locked access
	to a single git-style configuration file (ini like format, using tabs as improve readablity).
	
	Configuration readers can be initialized with multiple files at once, whose information is concatenated
	when reading. Lower-level files overwrite values from higher level files, i.e. a repository configuration file 
	overwrites information coming from a system configuration file
	
	:note: for the 'repository' config level, a git_path() compatible type is required"""
	config_level = ("system", "global", "repository")
		
	#{ Interface
	
	def config_reader(self, config_level=None):
		"""
		:return:
			GitConfigParser allowing to read the full git configuration, but not to write it
			
			The configuration will include values from the system, user and repository 
			configuration files.
			
		:param config_level:
			For possible values, see config_writer method
			If None, all applicable levels will be used. Specify a level in case 
			you know which exact file you whish to read to prevent reading multiple files for 
			instance
		:note: On windows, system configuration cannot currently be read as the path is 
			unknown, instead the global path will be used."""
		raise NotImplementedError()
		
	def config_writer(self, config_level="repository"):
		"""
		:return:
			GitConfigParser allowing to write values of the specified configuration file level.
			Config writers should be retrieved, used to change the configuration ,and written 
			right away as they will lock the configuration file in question and prevent other's
			to write it.
			
		:param config_level:
			One of the following values
			system = sytem wide configuration file
			global = user level configuration file
			repository = configuration file for this repostory only"""
		raise NotImplementedError()
	
	
	#} END interface
	
	
class SubmoduleDB(object):
	"""Interface providing access to git repository submodules.
	The actual implementation is found in the Submodule object type, which is
	currently only available in one implementation."""
	
	@property
	def submodules(self):
		"""
		:return: git.IterableList(Submodule, ...) of direct submodules
			available from the current head"""
		raise NotImplementedError()
		
	def submodule(self, name):
		""" :return: Submodule with the given name 
		:raise ValueError: If no such submodule exists"""
		raise NotImplementedError()
		
	def create_submodule(self, *args, **kwargs):
		"""Create a new submodule
		
		:note: See the documentation of Submodule.add for a description of the 
			applicable parameters
		:return: created submodules"""
		raise NotImplementedError()
		
	def iter_submodules(self, *args, **kwargs):
		"""An iterator yielding Submodule instances, see Traversable interface
		for a description of args and kwargs
		:return: Iterator"""
		raise NotImplementedError()
		
	def submodule_update(self, *args, **kwargs):
		"""Update the submodules, keeping the repository consistent as it will 
		take the previous state into consideration. For more information, please
		see the documentation of RootModule.update"""
		raise NotImplementedError()
		
		
class HighLevelRepository(object):
	"""An interface combining several high-level repository functionality and properties"""
	
	@property
	def daemon_export(self):
		""":return: True if the repository may be published by the git-daemon"""
		raise NotImplementedError()

	def is_dirty(self, index=True, working_tree=True, untracked_files=False):
		"""
		:return:
			``True``, the repository is considered dirty. By default it will react
			like a git-status without untracked files, hence it is dirty if the 
			index or the working copy have changes."""
		raise NotImplementedError()
		
	@property
	def untracked_files(self):
		"""
		:return:
			list(str,...)
			
		:note:
			ignored files will not appear here, i.e. files mentioned in .gitignore.
			Bare repositories never have untracked files"""
		raise NotImplementedError()

	def blame(self, rev, file):
		"""The blame information for the given file at the given revision.

		:parm rev: revision specifier, see git-rev-parse for viable options.
		:return:
			list: [Commit, list: [<line>]]
			A list of tuples associating a Commit object with a list of lines that 
			changed within the given commit. The Commit objects will be given in order
			of appearance."""
		raise NotImplementedError()
		
	@classmethod
	def init(cls, path=None, mkdir=True):
		"""Initialize a git repository at the given path if specified

		:param path:
			is the full path to the repo (traditionally ends with /<name>.git)
			or None in which case the repository will be created in the current 
			working directory

		:parm mkdir:
			if specified will create the repository directory if it doesn't
			already exists. Creates the directory with a mode=0755. 
			Only effective if a path is explicitly given

		:return: Instance pointing to the newly created repository with similar capabilities
			of this class"""
		raise NotImplementedError()

	def clone(self, path, progress = None):
		"""Create a clone from this repository.
		:param path:
			is the full path of the new repo (traditionally ends with ./<name>.git).

		:param progress:
			a RemoteProgress instance or None if no progress information is required
		
		:return: ``git.Repo`` (the newly cloned repo)"""
		raise NotImplementedError()

	@classmethod
	def clone_from(cls, url, to_path, progress = None):
		"""Create a clone from the given URL
		:param url: valid git url, see http://www.kernel.org/pub/software/scm/git/docs/git-clone.html#URLS
		:param to_path: Path to which the repository should be cloned to
		:param progress:
			a RemoteProgress instance or None if no progress information is required
		:return: instance pointing to the cloned directory with similar capabilities as this class"""
		raise NotImplementedError()

	def archive(self, ostream, treeish=None, prefix=None):
		"""Archive the tree at the given revision.
		:parm ostream: file compatible stream object to which the archive will be written
		:parm treeish: is the treeish name/id, defaults to active branch
		:parm prefix: is the optional prefix to prepend to each filename in the archive
		:parm kwargs:
			Additional arguments passed to git-archive
			NOTE: Use the 'format' argument to define the kind of format. Use 
			specialized ostreams to write any format supported by python
		:return: self"""
		raise NotImplementedError()
	
	
