# diff.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re
import objects.blob as blob

	
class Diffable(object):
	"""
	Common interface for all object that can be diffed against another object of compatible type.
	
	NOTE: 
		Subclasses require a repo member as it is the case for Object instances, for practical 
		reasons we do not derive from Object.
	"""
	__slots__ = tuple()
	
	# subclasses provide additional arguments to the git-diff comamnd by supplynig 
	# them in this tuple
	_diff_args = tuple()
	
	def diff(self, other=None, paths=None, create_patch=False, **kwargs):
		"""
		Creates diffs between two items being trees, trees and index or an 
		index and the working tree.

		``other``
			Is the item to compare us with. 
			If None, we will be compared to the working tree.

		``paths``
			is a list of paths or a single path to limit the diff to.
			It will only include at least one of the givne path or paths.

		``create_patch``
			If True, the returned Diff contains a detailed patch that if applied
			makes the self to other. Patches are somwhat costly as blobs have to be read
			and diffed.

		``kwargs``
			Additional arguments passed to git-diff, such as 
			R=True to swap both sides of the diff.

		Returns
			git.DiffIndex
			
		Note
			Rename detection will only work if create_patch is True
		"""
		args = list(self._diff_args[:])
		args.append( "--abbrev=40" )		# we need full shas
		args.append( "--full-index" )		# get full index paths, not only filenames
		
		if create_patch:
			args.append("-p")
			args.append("-M") # check for renames
		else:
			args.append("--raw")
		
		paths = paths or []
		if paths:
			paths.insert(0, "--")

		if other is not None:
			args.insert(0, other)
		
		args.insert(0,self)
		args.extend(paths)
		
		kwargs['as_process'] = True
		proc = self.repo.git.diff(*args, **kwargs)
		
		diff_method = Diff._index_from_raw_format
		if create_patch:
			diff_method = Diff._index_from_patch_format
		return diff_method(self.repo, proc.stdout)


class Diff(object):
	"""
	A Diff contains diff information between two Trees.
	
	It contains two sides a and b of the diff, members are prefixed with 
	"a" and "b" respectively to inidcate that.
	
	Diffs keep information about the changed blob objects, the file mode, renames, 
	deletions and new files.
	
	There are a few cases where None has to be expected as member variable value:
	
	``New File``::
	
		a_mode is None
		a_blob is None
		
	``Deleted File``::
	
		b_mode is None
		b_blob is NOne
	"""
	
	# precompiled regex
	re_header = re.compile(r"""
								#^diff[ ]--git
									[ ]a/(?P<a_path>\S+)[ ]b/(?P<b_path>\S+)\n
								(?:^similarity[ ]index[ ](?P<similarity_index>\d+)%\n
								   ^rename[ ]from[ ](?P<rename_from>\S+)\n
								   ^rename[ ]to[ ](?P<rename_to>\S+)(?:\n|$))?
								(?:^old[ ]mode[ ](?P<old_mode>\d+)\n
								   ^new[ ]mode[ ](?P<new_mode>\d+)(?:\n|$))?
								(?:^new[ ]file[ ]mode[ ](?P<new_file_mode>.+)(?:\n|$))?
								(?:^deleted[ ]file[ ]mode[ ](?P<deleted_file_mode>.+)(?:\n|$))?
								(?:^index[ ](?P<a_blob_id>[0-9A-Fa-f]+)
									\.\.(?P<b_blob_id>[0-9A-Fa-f]+)[ ]?(?P<b_mode>.+)?(?:\n|$))?
							""", re.VERBOSE | re.MULTILINE)
	re_is_null_hexsha = re.compile( r'^0{40}$' )
	__slots__ = ("a_blob", "b_blob", "a_mode", "b_mode", "new_file", "deleted_file", 
				 "rename_from", "rename_to", "renamed", "diff")

	def __init__(self, repo, a_path, b_path, a_blob_id, b_blob_id, a_mode,
				 b_mode, new_file, deleted_file, rename_from,
				 rename_to, diff):
		if not a_blob_id or self.re_is_null_hexsha.search(a_blob_id):
			self.a_blob = None
		else:
			self.a_blob = blob.Blob(repo, id=a_blob_id, mode=a_mode, path=a_path)
		if not b_blob_id or self.re_is_null_hexsha.search(b_blob_id):
			self.b_blob = None
		else:
			self.b_blob = blob.Blob(repo, id=b_blob_id, mode=b_mode, path=b_path)

		self.a_mode = a_mode
		self.b_mode = b_mode
		if self.a_mode:
			self.a_mode = blob.Blob._mode_str_to_int( self.a_mode )
		if self.b_mode:
			self.b_mode = blob.Blob._mode_str_to_int( self.b_mode )
		self.new_file = new_file
		self.deleted_file = deleted_file
		self.rename_from = rename_from
		self.rename_to = rename_to
		self.renamed = rename_from != rename_to
		self.diff = diff

	@classmethod
	def _index_from_patch_format(cls, repo, stream):
		"""
		Create a new DiffIndex from the given text which must be in patch format
		``repo``
			is the repository we are operating on - it is required 
		
		``stream``
			result of 'git diff' as a stream (supporting file protocol)
		
		Returns
			git.DiffIndex
		"""
		# for now, we have to bake the stream
		text = stream.read()
		diffs = []

		diff_header = cls.re_header.match
		for diff in ('\n' + text).split('\ndiff --git')[1:]:
			header = diff_header(diff)

			a_path, b_path, similarity_index, rename_from, rename_to, \
				old_mode, new_mode, new_file_mode, deleted_file_mode, \
				a_blob_id, b_blob_id, b_mode = header.groups()
			new_file, deleted_file = bool(new_file_mode), bool(deleted_file_mode)

			diffs.append(Diff(repo, a_path, b_path, a_blob_id, b_blob_id,
				old_mode or deleted_file_mode, new_mode or new_file_mode or b_mode,
				new_file, deleted_file, rename_from, rename_to, diff[header.end():]))

		return diffs
		
	@classmethod
	def _index_from_raw_format(cls, repo, stream):
		"""
		Create a new DiffIndex from the given stream which must be in raw format.
		
		Returns
			git.DiffIndex
		"""
		raise NotImplementedError("")

