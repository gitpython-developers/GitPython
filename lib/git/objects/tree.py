# tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import blob
import base
import binascii

def sha_to_hex(sha):
    """Takes a string and returns the hex of the sha within"""
    hexsha = binascii.hexlify(sha)
    assert len(hexsha) == 40, "Incorrect length of sha1 string: %d" % hexsha
    return hexsha

class Tree(base.IndexObject, base.Diffable):
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
	ascii_commit_id = (0x31 << 4) + 0x36		
	ascii_blob_id = (0x31 << 4) + 0x30
	ascii_tree_id = (0x34 << 4) + 0x30
	
	
	def __init__(self, repo, id, mode=0, path=None):
		super(Tree, self).__init__(repo, id, mode, path)

	def _set_cache_(self, attr):
		if attr == "_cache":
			# Set the data when we need it
			self._cache = self._get_tree_cache()
		else:
			super(Tree, self)._set_cache_(attr)

	def _get_tree_cache(self):
		"""
		Return
			list(object_instance, ...)
		
		``treeish``
			sha or ref identifying a tree  
		"""
		out = list()
		for obj in self._iter_from_data():
			if obj is not None:
				out.append(obj)
			# END if object was handled
		# END for each line from ls-tree
		return out
		
		
	def _iter_from_data(self):
		"""
		Reads the binary non-pretty printed representation of a tree and converts
		it into Blob, Tree or Commit objects.
		
		Note: This method was inspired by the parse_tree method in dulwich.
		
		Returns
			list(IndexObject, ...)
		"""
		ord_zero = ord('0')
		data = self.data
		len_data = len(data)
		i = 0
		while i < len_data:
			mode = 0
			mode_boundary = i + 6
			
			# keep it ascii - we compare against the respective values
			type_id = (ord(data[i])<<4) + ord(data[i+1])
			i += 2
			
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
			
			hexsha = sha_to_hex(sha)
			if type_id == self.ascii_blob_id:
				yield blob.Blob(self.repo, hexsha, mode, name)
			elif type_id == self.ascii_tree_id:
				yield Tree(self.repo, hexsha, mode, name)
			elif type_id == self.ascii_commit_id:
				# todo 
				yield None
			else:
				raise TypeError( "Unknown type found in tree data: %i" % type_id )
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
		return self[file]


	def __repr__(self):
		return '<git.Tree "%s">' % self.id
		
	@classmethod
	def _iter_recursive(cls, repo, tree, cur_depth, max_depth, predicate ):
		
		for obj in tree:
			# adjust path to be complete
			obj.path = os.path.join(tree.path, obj.path)
			if not predicate(obj):
				continue
			yield obj
			if obj.type == "tree" and ( max_depth < 0 or cur_depth+1 <= max_depth ):
				for recursive_obj in cls._iter_recursive( repo, obj, cur_depth+1, max_depth, predicate ):
					yield recursive_obj
				# END for each recursive object
			# END if we may enter recursion
		# END for each object
		
	def traverse(self, max_depth=-1, predicate = lambda i: True):
		"""
		Returns
		
			Iterator to traverse the tree recursively up to the given level.
			The iterator returns Blob and Tree objects
		
		``max_depth``
		
			if -1, the whole tree will be traversed
			if 0, only the first level will be traversed which is the same as 
			the default non-recursive iterator
			
		``predicate``
		
			If predicate(item) returns True, item will be returned by iterator
		"""
		return self._iter_recursive( self.repo, self, 0, max_depth, predicate )
		
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


	# List protocol
	def __getslice__(self,i,j):
		return self._cache[i:j]
		
	def __iter__(self):
		return iter(self._cache)
		
	def __len__(self):
		return len(self._cache)
		
	def __getitem__(self,item):
		if isinstance(item, int):
			return self._cache[item]
		
		if isinstance(item, basestring):
			# compatability
			for obj in self._cache:
				if obj.path == item:
					return obj
			# END for each obj
			raise KeyError( "Blob or Tree named %s not found" % item )
		# END index is basestring 
		
		raise TypeError( "Invalid index type: %r" % item )
		
		
	def __contains__(self,item):
		if isinstance(item, base.IndexObject):
			return item in self._cache
		
		# compatability
		for obj in self._cache:
			if item == obj.path:
				return True
		# END for each item
		return False
	
	def __reversed__(self):
		return reversed(self._cache)
