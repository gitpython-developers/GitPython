# tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import blob
import base

class Tree(base.IndexObject):
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
	
	def __init__(self, repo, id, mode=None, path=None):
		super(Tree, self).__init__(repo, id, mode, path)

	def _set_cache_(self, attr):
		if attr == "_cache":
			# Set the data when we need it
			self._cache = self._get_tree_cache(self.repo, self.id)
		else:
			super(Tree, self)._set_cache_(attr)

	@classmethod
	def _get_tree_cache(cls, repo, treeish):
		"""
		Return
			list(object_instance, ...)
		
		``treeish``
			sha or ref identifying a tree  
		"""
		out = list()
		for line in repo.git.ls_tree(treeish).splitlines():
			obj = cls.content_from_string(repo, line)
			if obj is not None:
				out.append(obj)
			# END if object was handled
		# END for each line from ls-tree
		return out
		

	@classmethod
	def content_from_string(cls, repo, text):
		"""
		Parse a content item and create the appropriate object

		``repo``
			is the Repo

		 ``text``
			is the single line containing the items data in `git ls-tree` format

		Returns
			``git.Blob`` or ``git.Tree``
			
		NOTE: Currently sub-modules are ignored !
		"""
		try:
			mode, typ, id, path = text.expandtabs(1).split(" ", 3)
		except:
			return None

		if typ == "tree":
			return Tree(repo, id, mode, path)
		elif typ == "blob":
			return blob.Blob(repo, id, mode, path)
		elif typ == "commit":
			# TODO: Return a submodule
			return None 
		else:
		  raise(TypeError, "Invalid type: %s" % typ)

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
