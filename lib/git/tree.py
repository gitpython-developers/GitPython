# tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import blob
import base

class Tree(base.IndexObject):
	
	type = "tree"
	__slots__ = "_contents"
	
	def __init__(self, repo, id, mode=None, path=None):
		super(Tree, self).__init__(repo, id, mode, path)

	def _set_cache_(self, attr):
		if attr == "_contents":
			# Read the tree contents.
			self._contents = {}
			for line in self.repo.git.ls_tree(self.id).splitlines():
				obj = self.content_from_string(self.repo, line)
				if obj is not None:
					self._contents[obj.path] = obj
		else:
			super(Tree, self)._set_cache_(attr)

	@staticmethod
	def content_from_string(repo, text):
		"""
		Parse a content item and create the appropriate object

		``repo``
			is the Repo

		 ``text``
			is the single line containing the items data in `git ls-tree` format

		Returns
			``git.Blob`` or ``git.Tree``
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
			``git.Blob`` or ``git.Tree`` or ``None`` if not found
		"""
		return self.get(file)


	def __repr__(self):
		return '<git.Tree "%s">' % self.id

	# Implement the basics of the dict protocol:
	# directories/trees can be seen as object dicts.
	def __getitem__(self, key):
		return self._contents[key]

	def __iter__(self):
		return iter(self._contents)

	def __len__(self):
		return len(self._contents)

	def __contains__(self, key):
		return key in self._contents

	def get(self, key):
		return self._contents.get(key)

	def items(self):
		return self._contents.items()

	def keys(self):
		return self._contents.keys()

	def values(self):
		return self._contents.values()
