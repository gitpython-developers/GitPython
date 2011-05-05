# tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.util import RepoAliasMixin
from gitdb.object.tree import Tree as GitDB_Tree
from gitdb.object.tree import TreeModifier
import git.diff as diff

from blob import Blob
from submodule.base import Submodule

__all__ = ("TreeModifier", "Tree")

class Tree(GitDB_Tree, diff.Diffable):
	"""As opposed to the default GitDB tree implementation, this one can be diffed
	and returns our own types"""
	__slots__ = tuple()
	
	_map_id_to_type = {
						GitDB_Tree.commit_id : Submodule, 
						GitDB_Tree.blob_id : Blob, 
						GitDB_Tree.symlink_id : Blob
						# tree id added once Tree is defined
						}
	
# finalize map definition
Tree._map_id_to_type[Tree.tree_id] = Tree
