# tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
from blob import Blob
from submodule import Submodule
import base
import binascii
import git.diff as diff
import utils
from git.utils import join_path

join = os.path.join

def sha_to_hex(sha):
	"""Takes a string and returns the hex of the sha within"""
	hexsha = binascii.hexlify(sha)
	return hexsha
	

class Tree(base.IndexObject, diff.Diffable, utils.Traversable, utils.Serializable):
	"""
	Tress represent a ordered list of Blobs and other Trees. Hence it can be 
	accessed like a list.
	
	Tree's will cache their contents after first retrieval to improve efficiency.
	
	``Tree as a list``::
		
		Access a specific blob using the  
		tree['filename'] notation.
		
		You may as well access by index
		blob = tree[0]
		
		
	"""
	
	type = "tree"
	__slots__ = "_cache"
	
	# using ascii codes for comparison 
	commit_id = 016		
	blob_id = 010
	symlink_id = 012
	tree_id = 004
	
	_map_id_to_type = {
						commit_id : Submodule, 
						blob_id : Blob, 
						symlink_id : Blob
						# tree id added once Tree is defined
						}
	
	
	def __init__(self, repo, sha, mode=0, path=None):
		super(Tree, self).__init__(repo, sha, mode, path)

	@classmethod
	def _get_intermediate_items(cls, index_object):
		if index_object.type == "tree":
			return tuple(index_object._iter_convert_to_object(index_object._cache))
		return tuple()

	def _set_cache_(self, attr):
		if attr == "_cache":
			# Set the data when we need it
			self._cache = self._get_tree_cache(self.data)
		else:
			super(Tree, self)._set_cache_(attr)

	def _get_tree_cache(self, data):
		""" :return: list(object_instance, ...)
		:param data: data string containing our serialized information"""
		return list(self._iter_from_data(data))
		
	def _iter_convert_to_object(self, iterable):
		"""Iterable yields tuples of (hexsha, mode, name), which will be converted
		to the respective object representation"""
		for hexsha, mode, name in iterable:
			path = join(self.path, name)
			type_id = mode >> 12
			try:
				yield self._map_id_to_type[type_id](self.repo, hexsha, mode, path)
			except KeyError:
				raise TypeError( "Unknown type %i found in tree data for path '%s'" % (type_id, path))
		# END for each item 
		
	def _iter_from_data(self, data):
		"""
		Reads the binary non-pretty printed representation of a tree and converts
		it into Blob, Tree or Commit objects.
		
		Note: This method was inspired by the parse_tree method in dulwich.
		
		:yield: Tuple(hexsha, mode, tree_relative_path)
		"""
		ord_zero = ord('0')
		len_data = len(data)
		i = 0
		while i < len_data:
			mode = 0
			
			# read mode
			# Some git versions truncate the leading 0, some don't
			# The type will be extracted from the mode later
			while data[i] != ' ':
				# move existing mode integer up one level being 3 bits
				# and add the actual ordinal value of the character
				mode = (mode << 3) + (ord(data[i]) - ord_zero)
				i += 1
			# END while reading mode
			
			# byte is space now, skip it
			i += 1
			
			# parse name, it is NULL separated
			
			ns = i
			while data[i] != '\0':
				i += 1
			# END while not reached NULL
			name = data[ns:i]
			
			# byte is NULL, get next 20
			i += 1
			sha = data[i:i+20]
			i = i + 20
			
			yield (sha_to_hex(sha), mode, name)
		# END for each byte in data stream


	def __div__(self, file):
		"""
		Find the named object in this tree's contents

		Examples::

			>>> Repo('/path/to/python-git').tree/'lib'
			<git.Tree "6cc23ee138be09ff8c28b07162720018b244e95e">
			>>> Repo('/path/to/python-git').tree/'README.txt'
			<git.Blob "8b1e02c0fb554eed2ce2ef737a68bb369d7527df">

		Returns
			``git.Blob`` or ``git.Tree``
		
		Raise 
			KeyError if given file or tree does not exist in tree
		"""
		msg = "Blob or Tree named %r not found"
		if '/' in file:
			tree = self
			item = self
			tokens = file.split('/')
			for i,token in enumerate(tokens):
				item = tree[token]
				if item.type == 'tree':
					tree = item
				else:
					# safety assertion - blobs are at the end of the path
					if i != len(tokens)-1:
						raise KeyError(msg % file)
					return item
				# END handle item type
			# END for each token of split path
			if item == self:
				raise KeyError(msg % file)
			return item
		else:
			for info in self._cache:
				if info[2] == file:		# [2] == name
					return self._map_id_to_type[info[1] >> 12](self.repo, info[0], info[1], join(self.path, info[2]))
			# END for each obj
			raise KeyError( msg % file )
		# END handle long paths


	def __repr__(self):
		return '<git.Tree "%s">' % self.sha
			
	@property
	def trees(self):
		"""
		Returns
			list(Tree, ...) list of trees directly below this tree
		"""
		return [ i for i in self if i.type == "tree" ]
		
	@property
	def blobs(self):
		"""
		Returns
			list(Blob, ...) list of blobs directly below this tree
		"""
		return [ i for i in self if i.type == "blob" ]


	def traverse( self, predicate = lambda i,d: True,
						   prune = lambda i,d: False, depth = -1, branch_first=True,
						   visit_once = False, ignore_self=1 ):
		"""For documentation, see utils.Traversable.traverse
		
		Trees are set to visit_once = False to gain more performance in the traversal"""
		return super(Tree, self).traverse(predicate, prune, depth, branch_first, visit_once, ignore_self)

	# List protocol
	def __getslice__(self, i, j):
		return list(self._iter_convert_to_object(self._cache[i:j]))
		
	def __iter__(self):
		return self._iter_convert_to_object(self._cache)
		
	def __len__(self):
		return len(self._cache)
		
	def __getitem__(self, item):
		if isinstance(item, int):
			info = self._cache[item]
			return self._map_id_to_type[info[1] >> 12](self.repo, info[0], info[1], join(self.path, info[2]))
		
		if isinstance(item, basestring):
			# compatability
			return self.__div__(item)
		# END index is basestring 
		
		raise TypeError( "Invalid index type: %r" % item )
		
		
	def __contains__(self, item):
		if isinstance(item, base.IndexObject):
			for info in self._cache:
				if item.sha == info[0]:
					return True
				# END compare sha
			# END for each entry
		# END handle item is index object
		# compatability
		
		# treat item as repo-relative path
		path = self.path
		for info in self._cache:
			if item == join(path, info[2]):
				return True
		# END for each item
		return False
	
	def __reversed__(self):
		return reversed(self._iter_convert_to_object(self._cache))
		
	def _serialize(self, stream, presort=False):
		"""Serialize this tree into the stream. Please note that we will assume 
		our tree data to be in a sorted state. If this is not the case, set the 
		presort flag True
		:param presort: if True, default False, sort our tree information before
			writing it to the stream. This should be done if the cache changed
			in the meanwhile"""
		ord_zero = ord('0')
		bit_mask = 7			# 3 bits set
		hex_to_bin = binascii.a2b_hex
		
		for hexsha, mode, name in self._cache:
			mode_str = ''
			for i in xrange(6):
				mode_str = chr(((mode >> (i*3)) & bit_mask) + ord_zero) + mode_str
			# END for each 8 octal value
			
			# git slices away the first octal if its zero
			if mode_str[0] == '0':
				mode_str = mode_str[1:]
			# END save a byte

			stream.write("%s %s\0%s" % (mode_str, name, hex_to_bin(hexsha))) 
		# END for each item
		return self
		
	def _deserialize(self, stream):
		self._cache = self._get_tree_cache(stream.read())
		return self
		
		
# END tree

# finalize map definition
Tree._map_id_to_type[Tree.tree_id] = Tree
