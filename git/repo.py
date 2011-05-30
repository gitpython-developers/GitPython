# repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""This module is just to maintain compatibility to git-python 0.3x"""

from git.db.complex import CmdCompatibilityGitDB


import warnings

__all__ = ('Repo', )


class Repo(CmdCompatibilityGitDB):
	"""Represents a git repository and allows you to query references, 
	gather commit information, generate diffs, create and clone repositories query
	the log.
	
	The following attributes are worth using:
	
	'working_dir' is the working directory of the git command, wich is the working tree 
	directory if available or the .git directory in case of bare repositories
	
	'working_tree_dir' is the working tree directory, but will raise AssertionError
	if we are a bare repository.
	
	'git_dir' is the .git repository directoy, which is always set."""
	
	def __init__(self, path=None, odbt = None):
		"""Create a new Repo instance

		:param path: is the path to either the root git directory or the bare git repo::

			repo = Repo("/Users/mtrier/Development/git-python")
			repo = Repo("/Users/mtrier/Development/git-python.git")
			repo = Repo("~/Development/git-python.git")
			repo = Repo("$REPOSITORIES/Development/git-python.git")
		:raise InvalidDBRoot:
		:return: git.Repo """
		if odbt is not None:
			warnings.warn("deprecated use of odbt", DeprecationWarning)
		#END handle old parameter
		super(Repo, self).__init__(path)
