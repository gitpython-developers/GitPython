# index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing Index implementation, allowing to perform all kinds of index
manipulations such as querying and merging.
"""
import struct
import binascii
import mmap
import objects
import tempfile
import os
import sys
import stat
import subprocess
import git.diff as diff

from git.objects import Blob, Tree, Object, Commit
from git.utils import SHA1Writer, LazyMixin, ConcurrentWriteOperation, join_path_native


class _TemporaryFileSwap(object):
	"""
	Utility class moving a file to a temporary location within the same directory
	and moving it back on to where on object deletion.
	"""
	__slots__ = ("file_path", "tmp_file_path")
	
	def __init__(self, file_path):
		self.file_path = file_path
		self.tmp_file_path = self.file_path + tempfile.mktemp('','','')
		os.rename(self.file_path, self.tmp_file_path)
		
	def __del__(self):
		if os.path.isfile(self.tmp_file_path):
			if os.name == 'nt' and os.path.exists(self.file_path):
				os.remove(self.file_path)
			os.rename(self.tmp_file_path, self.file_path)
		# END temp file exists
	

class BaseIndexEntry(tuple):
	"""
	
	Small Brother of an index entry which can be created to describe changes
	done to the index in which case plenty of additional information is not requried.
	
	As the first 4 data members match exactly to the IndexEntry type, methods
	expecting a BaseIndexEntry can also handle full IndexEntries even if they
	use numeric indices for performance reasons.
	"""
	
	def __str__(self):
		return "%o %s %i\t%s\n" % (self.mode, self.sha, self.stage, self.path)
	
	@property
	def mode(self):
		"""
		File Mode, compatible to stat module constants
		"""
		return self[0]
		
	@property
	def sha(self):
		"""
		hex sha of the blob
		"""
		return self[1]
		
	@property
	def stage(self):
		"""
		Stage of the entry, either:
			0 = default stage
			1 = stage before a merge or common ancestor entry in case of a 3 way merge
			2 = stage of entries from the 'left' side of the merge
			3 = stage of entries from the right side of the merge
		Note:
			For more information, see http://www.kernel.org/pub/software/scm/git/docs/git-read-tree.html
		"""
		return self[2]

	@property
	def path(self):
		return self[3]
		
	@classmethod
	def from_blob(cls, blob, stage = 0):
		"""
		Returns
			Fully equipped BaseIndexEntry at the given stage
		"""
		return cls((blob.mode, blob.sha, stage, blob.path))
		

class IndexEntry(BaseIndexEntry):
	"""
	Allows convenient access to IndexEntry data without completely unpacking it.
	
	Attributes usully accessed often are cached in the tuple whereas others are 
	unpacked on demand.
	
	See the properties for a mapping between names and tuple indices.
	"""
	@property
	def ctime(self):
		"""
		Returns
			Tuple(int_time_seconds_since_epoch, int_nano_seconds) of the 
			file's creation time
		"""
		return struct.unpack(">LL", self[4])
		
	@property
	def mtime(self):
		"""
		See ctime property, but returns modification time
		"""
		return struct.unpack(">LL", self[5])
	
	@property
	def dev(self):
		"""
		Device ID
		"""
		return self[6] 
	
	@property
	def inode(self):
		"""
		Inode ID
		"""
		return self[7]
	
	@property
	def uid(self):
		"""
		User ID
		"""
		return self[8]
		
	@property
	def gid(self):
		"""
		Group ID
		"""
		return self[9]

	@property
	def size(self):
		"""
		Uncompressed size of the blob
		
		Note
			Will be 0 if the stage is not 0 ( hence it is an unmerged entry )
		"""
		return self[10]
		
	@classmethod
	def from_blob(cls, blob):
		"""
		Returns
			Minimal entry resembling the given blob objecft
		"""
		time = struct.pack(">LL", 0, 0)
		return IndexEntry((blob.mode, blob.sha, 0, blob.path, time, time, 0, 0, 0, 0, blob.size))


def clear_cache(func):
	"""
	Decorator for functions that alter the index using the git command. This would 
	invalidate our possibly existing entries dictionary which is why it must be 
	deleted to allow it to be lazily reread later.
	
	Note
		This decorator will not be required once all functions are implemented 
		natively which in fact is possible, but probably not feasible performance wise.
	"""
	def clear_cache_if_not_raised(self, *args, **kwargs):
		rval = func(self, *args, **kwargs)
		del(self.entries)
		return rval
			
	# END wrapper method 
	clear_cache_if_not_raised.__name__ = func.__name__
	return clear_cache_if_not_raised
	

def default_index(func):
	"""
	Decorator assuring the wrapped method may only run if we are the default 
	repository index. This is as we rely on git commands that operate 
	on that index only.
	"""
	def check_default_index(self, *args, **kwargs):
		if self._file_path != self._index_path():
			raise AssertionError( "Cannot call %r on indices that do not represent the default git index" % func.__name__ )
		return func(self, *args, **kwargs)
	# END wrpaper method
	
	check_default_index.__name__ = func.__name__
	return check_default_index


class IndexFile(LazyMixin, diff.Diffable):
	"""
	Implements an Index that can be manipulated using a native implementation in 
	order to save git command function calls wherever possible.
	
	It provides custom merging facilities allowing to merge without actually changing
	your index or your working tree. This way you can perform own test-merges based
	on the index only without having to deal with the working copy. This is useful 
	in case of partial working trees.
	
	``Entries``
	The index contains an entries dict whose keys are tuples of type IndexEntry
	to facilitate access.
	
	You may only read the entries dict or manipulate it through designated methods.
	Otherwise changes to it will be lost when changing the index using its methods.
	"""
	__slots__ = ( "repo", "version", "entries", "_extension_data", "_file_path" )
	_VERSION = 2			# latest version we support
	S_IFGITLINK	= 0160000
	
	def __init__(self, repo, file_path=None):
		"""
		Initialize this Index instance, optionally from the given ``file_path``.
		If no file_path is given, we will be created from the current index file.
		
		If a stream is not given, the stream will be initialized from the current 
		repository's index on demand.
		"""
		self.repo = repo
		self.version = self._VERSION
		self._extension_data = ''
		self._file_path = file_path or self._index_path()
	
	def _set_cache_(self, attr):
		if attr == "entries":
			# read the current index
			# try memory map for speed
			fp = open(self._file_path, "rb")
			stream = fp
			try:
				raise Exception()
				stream = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
			except Exception:
				pass
			# END memory mapping
			
			try:
				self._read_from_stream(stream)
			finally:
				pass
				# make sure we close the stream ( possibly an mmap )
				# and the file
				#stream.close()
				#if stream is not fp:
				#	fp.close()
			# END read from default index on demand
		else:
			super(IndexFile, self)._set_cache_(attr)
	
	def _index_path(self):
		return join_path_native(self.repo.path, "index")
	
	
	@property
	def path(self):
		"""
		Returns 
			Path to the index file we are representing
		"""
		return self._file_path
	
	@classmethod
	def _read_entry(cls, stream):
		"""Return: One entry of the given stream"""
		beginoffset = stream.tell()
		ctime = struct.unpack(">8s", stream.read(8))[0]
		mtime = struct.unpack(">8s", stream.read(8))[0]
		(dev, ino, mode, uid, gid, size, sha, flags) = \
			struct.unpack(">LLLLLL20sH", stream.read(20 + 4 * 6 + 2))
		path_size = flags & 0x0fff
		path = stream.read(path_size)
		
		real_size = ((stream.tell() - beginoffset + 8) & ~7)
		data = stream.read((beginoffset + real_size) - stream.tell())
		return IndexEntry((mode, binascii.hexlify(sha), flags >> 12, path, ctime, mtime, dev, ino, uid, gid, size))
		
	@classmethod
	def _read_header(cls, stream):
		"""Return tuple(version_long, num_entries) from the given stream"""
		type_id = stream.read(4)
		if type_id != "DIRC":
			raise AssertionError("Invalid index file header: %r" % type_id)
		version, num_entries = struct.unpack(">LL", stream.read(4 * 2))
		assert version in (1, 2)
		return version, num_entries
		
	def _read_from_stream(self, stream):
		"""
		Initialize this instance with index values read from the given stream
		"""
		self.version, num_entries = self._read_header(stream)
		count = 0
		self.entries = dict()
		while count < num_entries:
			entry = self._read_entry(stream)
			self.entries[(entry.path, entry.stage)] = entry
			count += 1
		# END for each entry
		
		# the footer contains extension data and a sha on the content so far
		# Keep the extension footer,and verify we have a sha in the end
		self._extension_data = stream.read(~0)
		assert len(self._extension_data) > 19, "Index Footer was not at least a sha on content as it was only %i bytes in size" % len(self._extension_data)
		
		content_sha = self._extension_data[-20:]
		
		# truncate the sha in the end as we will dynamically create it anyway 
		self._extension_data = self._extension_data[:-20]
	
	
	@classmethod
	def _write_cache_entry(cls, stream, entry):
		"""
		Write an IndexEntry to a stream
		"""
		beginoffset = stream.tell()
		stream.write(entry[4])			# ctime
		stream.write(entry[5])			# mtime
		path = entry[3]
		plen = len(path) & 0x0fff		# path length
		assert plen == len(path), "Path %s too long to fit into index" % entry[3]
		flags = plen | (entry[2] << 12)# stage and path length are 2 byte flags
		stream.write(struct.pack(">LLLLLL20sH", entry[6], entry[7], entry[0], 
									entry[8], entry[9], entry[10], binascii.unhexlify(entry[1]), flags))
		stream.write(path)
		real_size = ((stream.tell() - beginoffset + 8) & ~7)
		stream.write("\0" * ((beginoffset + real_size) - stream.tell()))

	def write(self, file_path = None):
		"""
		Write the current state to our file path or to the given one
		
		``file_path``
			If None, we will write to our stored file path from which we have 
			been initialized. Otherwise we write to the given file path.
			Please note that this will change the file_path of this index to 
			the one you gave.
		
		Returns
			self
		
		Note
			Index writing based on the dulwich implementation
		"""
		write_op = ConcurrentWriteOperation(file_path or self._file_path)
		stream = write_op._begin_writing()
		
		stream = SHA1Writer(stream)
		
		# header
		stream.write("DIRC")
		stream.write(struct.pack(">LL", self.version, len(self.entries)))
		
		# body
		entries_sorted = self.entries.values()
		entries_sorted.sort(key=lambda e: (e[3], e[2]))		# use path/stage as sort key
		for entry in entries_sorted:
			self._write_cache_entry(stream, entry)
		# END for each entry
		
		# write previously cached extensions data
		stream.write(self._extension_data)
		
		# write the sha over the content
		stream.write_sha()
		write_op._end_writing()
		
		# make sure we represent what we have written
		if file_path is not None:
			self._file_path = file_path
	
	@classmethod
	def from_tree(cls, repo, *treeish, **kwargs):
		"""
		Merge the given treeish revisions into a new index which is returned.
		The original index will remain unaltered
		
		``repo``
			The repository treeish are located in.
			
		``*treeish``
			One, two or three Tree Objects or Commits. The result changes according to the 
			amount of trees.
			If 1 Tree is given, it will just be read into a new index
			If 2 Trees are given, they will be merged into a new index using a 
			 two way merge algorithm. Tree 1 is the 'current' tree, tree 2 is the 'other'
			 one. It behaves like a fast-forward.
			 If 3 Trees are given, a 3-way merge will be performed with the first tree
			 being the common ancestor of tree 2 and tree 3. Tree 2 is the 'current' tree, 
			 tree 3 is the 'other' one
			 
		``**kwargs``
			Additional arguments passed to git-read-tree
			
		Returns
			New IndexFile instance. It will point to a temporary index location which 
			does not exist anymore. If you intend to write such a merged Index, supply
			an alternate file_path to its 'write' method.
			
		Note:
			In the three-way merge case, --aggressive will be specified to automatically
			resolve more cases in a commonly correct manner. Specify trivial=True as kwarg
			to override that.
			
			As the underlying git-read-tree command takes into account the current index, 
			it will be temporarily moved out of the way to assure there are no unsuspected
			interferences.
		"""
		if len(treeish) == 0 or len(treeish) > 3:
			raise ValueError("Please specify between 1 and 3 treeish, got %i" % len(treeish))
		
		arg_list = list()
		# ignore that working tree and index possibly are out of date
		if len(treeish)>1:
			# drop unmerged entries when reading our index and merging
			arg_list.append("--reset")	
			# handle non-trivial cases the way a real merge does
			arg_list.append("--aggressive")	
		# END merge handling
		
		# tmp file created in git home directory to be sure renaming 
		# works - /tmp/ dirs could be on another device
		tmp_index = tempfile.mktemp('','',repo.path)
		arg_list.append("--index-output=%s" % tmp_index)
		arg_list.extend(treeish)
		
		# move current index out of the way - otherwise the merge may fail
		# as it considers existing entries. moving it essentially clears the index.
		# Unfortunately there is no 'soft' way to do it.
		# The _TemporaryFileSwap assure the original file get put back
		index_handler = _TemporaryFileSwap(join_path_native(repo.path, 'index'))
		try:
			repo.git.read_tree(*arg_list, **kwargs)
			index = cls(repo, tmp_index)
			index.entries		# force it to read the file
		finally:
			if os.path.exists(tmp_index):
				os.remove(tmp_index)
		# END index merge handling
		
		return index
	
	@classmethod
	def _index_mode_to_tree_index_mode(cls, index_mode):
		"""
		Cleanup a index_mode value.
		This will return a index_mode that can be stored in a tree object.
		
		``index_mode``
			Index_mode to clean up.
		"""
		if stat.S_ISLNK(index_mode):
			return stat.S_IFLNK
		elif stat.S_ISDIR(index_mode):
			return stat.S_IFDIR
		elif stat.S_IFMT(index_mode) == cls.S_IFGITLINK:
			return cls.S_IFGITLINK
		ret = stat.S_IFREG | 0644
		ret |= (index_mode & 0111)
		return ret
	
	@classmethod
	def _tree_mode_to_index_mode(cls, tree_mode):
		"""
		Convert a tree mode to index mode as good as possible
		"""
	
	def iter_blobs(self, predicate = lambda t: True):
		"""
		Returns
			Iterator yielding tuples of Blob objects and stages, tuple(stage, Blob)
			
		``predicate``
			Function(t) returning True if tuple(stage, Blob) should be yielded by the 
			iterator
		"""
		for entry in self.entries.itervalues():
			mode = self._index_mode_to_tree_index_mode(entry.mode)
			blob = Blob(self.repo, entry.sha, mode, entry.path)
			blob.size = entry.size
			output = (entry.stage, blob)
			if predicate(output):
				yield output
		# END for each entry 
	
	def unmerged_blobs(self):
		"""
		Returns
			Iterator yielding dict(path : list( tuple( stage, Blob, ...))), being 
			a dictionary associating a path in the index with a list containing 
			stage/blob pairs
			
		Note:
			Blobs that have been removed in one side simply do not exist in the 
			given stage. I.e. a file removed on the 'other' branch whose entries
			are at stage 3 will not have a stage 3 entry.
		"""
		is_unmerged_blob = lambda t: t[0] != 0
		path_map = dict()
		for stage, blob in self.iter_blobs(is_unmerged_blob):
			path_map.setdefault(blob.path, list()).append((stage, blob))
		# END for each unmerged blob
		
		return path_map
	
	def resolve_blobs(self, iter_blobs):
		"""
		Resolve the blobs given in blob iterator. This will effectively remove the 
		index entries of the respective path at all non-null stages and add the given 
		blob as new stage null blob.
		
		For each path there may only be one blob, otherwise a ValueError will be raised
		claiming the path is already at stage 0.
		
		Raise
			ValueError if one of the blobs already existed at stage 0
		
		Returns:
			self
			
		Note
			You will have to write the index manually once you are done, i.e.
			index.resolve_blobs(blobs).write()
		"""
		for blob in iter_blobs:
			stage_null_key = (blob.path, 0)
			if stage_null_key in self.entries:
				raise ValueError( "Blob %r already at stage 0" % blob )
			# END assert blob is not stage 0 already 
			
			# delete all possible stages
			for stage in (1, 2, 3):
				try:
					del( self.entries[(blob.path, stage)] )
				except KeyError:
					pass 
				# END ignore key errors
			# END for each possible stage
			
			self.entries[stage_null_key] = IndexEntry.from_blob(blob) 
		# END for each blob
		
		return self
		
	def update(self):
		"""
		Reread the contents of our index file, discarding all cached information 
		we might have.
		
		Note:
			This is a possibly dangerious operations as it will discard your changes
			to index.entries
			
		Returns
			self
		"""
		del(self.entries)
		# allows to lazily reread on demand
		return self
	
	def write_tree(self):
		"""
		Writes the Index in self to a corresponding Tree file into the repository
		object database and returns it as corresponding Tree object.
		
		Returns
			Tree object representing this index
		"""
		index_path = self._index_path()
		tmp_index_mover = _TemporaryFileSwap(index_path)
		
		self.write(index_path)
		tree_sha = self.repo.git.write_tree()
		
		return Tree(self.repo, tree_sha, 0, '')
		
	def _process_diff_args(self, args):
		try:
			args.pop(args.index(self))
		except IndexError:
			pass
		# END remove self
		return args
		
	
	def _to_relative_path(self, path):
		"""
		Return	
			Version of path relative to our git directory or raise ValueError
			if it is not within our git direcotory
		"""
		if not os.path.isabs(path):
			return path
		relative_path = path.replace(self.repo.git.git_dir+os.sep, "")
		if relative_path == path:
			raise ValueError("Absolute path %r is not in git repository at %r" % (path,self.repo.git.git_dir))
		return relative_path
	
	def _preprocess_add_items(self, items):
		"""
		Split the items into two lists of path strings and BaseEntries.
		"""
		paths = list()
		entries = list()
		
		for item in items:
			if isinstance(item, basestring):
				paths.append(self._to_relative_path(item))
			elif isinstance(item, Blob):
				entries.append(BaseIndexEntry.from_blob(item))
			elif isinstance(item, BaseIndexEntry):
				entries.append(item)
			else:
				raise TypeError("Invalid Type: %r" % item)
		# END for each item
		return (paths, entries)
		
	
	@clear_cache
	@default_index
	def add(self, items, force=True, **kwargs):
		"""
		Add files from the working tree, specific blobs or BaseIndexEntries 
		to the index. The underlying index file will be written immediately, hence
		you should provide as many items as possible to minimize the amounts of writes
		
		``items``
			Multiple types of items are supported, types can be mixed within one call.
			Different types imply a different handling. File paths may generally be 
			relative or absolute.
			
			- path string
				strings denote a relative or absolute path into the repository pointing to 
				an existing file, i.e. CHANGES, lib/myfile.ext, '/home/gitrepo/lib/myfile.ext'.
				
				Paths provided like this must exist. When added, they will be written 
				into the object database.
				
				PathStrings may contain globs, such as 'lib/__init__*' or can be directories
				like 'lib', the latter ones will add all the files within the dirctory and 
				subdirectories.
				
				This equals a straight git-add.
				
				They are added at stage 0
				
			- Blob object
				Blobs are added as they are assuming a valid mode is set.
				The file they refer to may or may not exist in the file system, but 
				must be a path relative to our repository.
				
				If their sha is null ( 40*0 ), their path must exist in the file system 
				as an object will be created from the data at the path.The handling 
				now very much equals the way string paths are processed, except that
				the mode you have set will be kept. This allows you to create symlinks
				by settings the mode respectively and writing the target of the symlink 
				directly into the file. This equals a default Linux-Symlink which 
				is not dereferenced automatically, except that it can be created on 
				filesystems not supporting it as well.
				
				Please note that globs or directories are not allowed in Blob objects. 
				
				They are added at stage 0
				
			- BaseIndexEntry or type
				Handling equals the one of Blob objects, but the stage may be 
				explicitly set.
			
		``force``
			If True, otherwise ignored or excluded files will be 
			added anyway.
			As opposed to the git-add command, we enable this flag by default 
			as the API user usually wants the item to be added even though 
			they might be excluded.
		
		``**kwargs``
			Additional keyword arguments to be passed to git-update-index, such 
			as index_only.
			
		Returns
			List(BaseIndexEntries) representing the entries just actually added.
		"""
		# sort the entries into strings and Entries, Blobs are converted to entries
		# automatically
		# paths can be git-added, for everything else we use git-update-index
		entries_added = list()
		paths, entries = self._preprocess_add_items(items)
		
		if paths:
			git_add_output = self.repo.git.add(paths, v=True)
			# force rereading our entries
			del(self.entries)
			for line in git_add_output.splitlines():
				# line contains:
				# add '<path>'
				added_file = line[5:-1]
				entries_added.append(self.entries[(added_file,0)])
			# END for each line
		# END path handling
		
		if entries:
			null_mode_entries = [ e for e in entries if e.mode == 0 ]
			if null_mode_entries:
				raise ValueError("At least one Entry has a null-mode - please use index.remove to remove files for clarity")
			# END null mode should be remove
			
			# create objects if required, otherwise go with the existing shas
			null_entries_indices = [ i for i,e in enumerate(entries) if e.sha == Object.NULL_HEX_SHA ]
			if null_entries_indices:
				hash_proc = self.repo.git.hash_object(w=True, stdin_paths=True, istream=subprocess.PIPE, as_process=True)
				hash_proc.stdin.write('\n'.join(entries[i].path for i in null_entries_indices))
				obj_ids = self._flush_stdin_and_wait(hash_proc).splitlines()
				assert len(obj_ids) == len(null_entries_indices), "git-hash-object did not produce all requested objects: want %i, got %i" % ( len(null_entries_indices), len(obj_ids) )
				
				# update IndexEntries with new object id
				for i,new_sha in zip(null_entries_indices, obj_ids):
					e = entries[i]
					new_entry = BaseIndexEntry((e.mode, new_sha, e.stage, e.path))
					entries[i] = new_entry
				# END for each index
			# END null_entry handling
				
			# feed all the data to stdin
			update_index_proc = self.repo.git.update_index(index_info=True, istream=subprocess.PIPE, as_process=True, **kwargs)
			update_index_proc.stdin.write('\n'.join(str(e) for e in entries))
			entries_added.extend(entries)
			self._flush_stdin_and_wait(update_index_proc)
		# END if there are base entries
		
		return entries_added
		
	@clear_cache
	@default_index
	def remove(self, items, working_tree=False, **kwargs):
		"""
		Remove the given items from the index and optionally from 
		the working tree as well.
		
		``items``
			Multiple types of items are supported which may be be freely mixed.
			
			- path string
				Remove the given path at all stages. If it is a directory, you must 
				specify the r=True keyword argument to remove all file entries 
				below it. If absolute paths are given, they will be converted 
				to a path relative to the git repository directory containing 
				the working tree
				
				The path string may include globs, such as *.c.
		
			- Blob object
				Only the path portion is used in this case.
				
			- BaseIndexEntry or compatible type
				The only relevant information here Yis the path. The stage is ignored.
		
		``working_tree``
			If True, the entry will also be removed from the working tree, physically
			removing the respective file. This may fail if there are uncommited changes
			in it.
			
		``**kwargs``
			Additional keyword arguments to be passed to git-rm, such 
			as 'r' to allow recurive removal of 
			
		Returns
			List(path_string, ...) list of paths that have been removed effectively.
			This is interesting to know in case you have provided a directory or 
			globs. Paths are relative to the 
		"""
		args = list()
		if not working_tree:
			args.append("--cached")
		args.append("--")
		
		# preprocess paths
		paths = list()
		for item in items:
			if isinstance(item, (BaseIndexEntry,Blob)):
				paths.append(self._to_relative_path(item.path))
			elif isinstance(item, basestring):
				paths.append(self._to_relative_path(item))
			else:
				raise TypeError("Invalid item type: %r" % item)
		# END for each item
		
		removed_paths = self.repo.git.rm(args, paths, **kwargs).splitlines()
		
		# process output to gain proper paths
		# rm 'path'
		return [ p[4:-1] for p in removed_paths ]
		
	@default_index
	def commit(self, message, parent_commits=None, head=True):
		"""
		Commit the current index, creating a commit object.
		
		``message``
			Commit message. It may be an empty string if no message is provided.
			It will be converted to a string in any case.
			
		``parent_commits``
			Optional Commit objects to use as parents for the new commit.
			If empty list, the commit will have no parents at all and become 
			a root commit.
			If None , the current head commit will be the parent of the 
			new commit object
			
		``head``
			If True, the HEAD will be advanced to the new commit automatically.
			Else the HEAD will remain pointing on the previous commit. This could 
			lead to undesired results when diffing files.
			
		Returns
			Commit object representing the new commit
			
		Note:
			Additional information about hte committer and Author are taken from the
			environment or from the git configuration, see git-commit-tree for 
			more information
		"""
		parents = parent_commits
		if parent_commits is None:
			parent_commits = [ self.repo.head.commit ]
		
		parent_args = [ ("-p", str(commit)) for commit in parent_commits ]
		
		# create message stream
		tmp_file_path = tempfile.mktemp()
		fp = open(tmp_file_path,"wb")
		fp.write(str(message))
		fp.close()
		fp = open(tmp_file_path,"rb")
		fp.seek(0)
		
		try:
			# write the current index as tree
			tree_sha = self.repo.git.write_tree()
			commit_sha = self.repo.git.commit_tree(tree_sha, parent_args, istream=fp)
			new_commit = Commit(self.repo, commit_sha)
			
			if head:
				self.repo.head.commit = new_commit 
			# END advance head handling 
			
			return new_commit
		finally:
			fp.close()
			os.remove(tmp_file_path)
			
	@classmethod
	def _flush_stdin_and_wait(cls, proc):
		proc.stdin.flush()
		proc.stdin.close()
		stdout = proc.stdout.read()
		proc.wait()
		return stdout
	
	@default_index
	def checkout(self, paths=None, force=False, **kwargs):
		"""
		Checkout the given paths or all files from the version in the index.
		
		``paths``
			If None, all paths in the index will be checked out. Otherwise an iterable
			or single path of relative or absolute paths pointing to files is expected.
			The command will ignore paths that do not exist.
			
		``force``
			If True, existing files will be overwritten. If False, these will 
			be skipped.
			
		``**kwargs``
			Additional arguments to be pasesd to git-checkout-index
			
		Returns
			self
		"""
		args = ["--index"]
		if force:
			args.append("--force")
		
		if paths is None:
			args.append("--all")
			self.repo.git.checkout_index(*args, **kwargs)
		else:
			if not isinstance(paths, (tuple,list)):
				paths = [paths]
				
			args.append("--stdin")
			paths = [self._to_relative_path(p) for p in paths]
			co_proc = self.repo.git.checkout_index(args, as_process=True, istream=subprocess.PIPE, **kwargs)
			co_proc.stdin.write('\n'.join(paths))
			self._flush_stdin_and_wait(co_proc)
		# END paths handling 
		return self
			
	@clear_cache
	@default_index
	def reset(self, commit='HEAD', working_tree=False, paths=None, head=False, **kwargs):
		"""
		Reset the index to reflect the tree at the given commit. This will not
		adjust our HEAD reference as opposed to HEAD.reset by default.
		
		``commit``
			Revision, Reference or Commit specifying the commit we should represent.
			If you want to specify a tree only, use IndexFile.from_tree and overwrite
			the default index.
			
		``working_tree``
			If True, the files in the working tree will reflect the changed index.
			If False, the working tree will not be touched
			Please note that changes to the working copy will be discarded without 
			warning !
			
		``head``
			If True, the head will be set to the given commit. This is False by default, 
			but if True, this method behaves like HEAD.reset.
			
		``**kwargs``
			Additional keyword arguments passed to git-reset
			
		Returns
			self
		"""
		cur_head = self.repo.head
		prev_commit = cur_head.commit
		
		# reset to get the tree/working copy
		cur_head.reset(commit, index=True, working_tree=working_tree, paths=paths, **kwargs)
		
		# put the head back, possibly
		if not head:
			cur_head.reset(prev_commit, index=False, working_tree=False)
		# END reset head
		
		return self
		
	@default_index
	def diff(self, other=diff.Diffable.Index, paths=None, create_patch=False, **kwargs):
		"""
		Diff this index against the working copy or a Tree or Commit object
		
		For a documentation of the parameters and return values, see 
		Diffable.diff
		
		Note
			Will only work with indices that represent the default git index as 
			they have not been initialized with a stream.
		"""
		# index against index is always empty
		if other is self.Index:
			return diff.DiffIndex()
			
		# index against anything but None is a reverse diff with the respective
		# item. Handle existing -R flags properly. Transform strings to the object
		# so that we can call diff on it
		if isinstance(other, basestring):
			other = Object.new(self.repo, other)
		# END object conversion
		
		if isinstance(other, Object):
			# invert the existing R flag
			cur_val = kwargs.get('R', False)
			kwargs['R'] = not cur_val
			return other.diff(self.Index, paths, create_patch, **kwargs)
		# END diff against other item handlin
		
		# if other is not None here, something is wrong 
		if other is not None:
			raise ValueError( "other must be None, Diffable.Index, a Tree or Commit, was %r" % other )
		
		# diff against working copy - can be handled by superclass natively
		return super(IndexFile, self).diff(other, paths, create_patch, **kwargs)
	
