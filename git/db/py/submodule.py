# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.objects.submodule.base import Submodule
from git.objects.submodule.root import RootModule
from git.db.interface import SubmoduleDB

__all__ = ["PureSubmoduleDB"]

class PureSubmoduleDB(SubmoduleDB):
	"""Pure python implementation of submodule functionality"""
	
	@property
	def submodules(self):
		return Submodule.list_items(self)
		
	def submodule(self, name):
		try:
			return self.submodules[name]
		except IndexError:
			raise ValueError("Didn't find submodule named %r" % name)
		# END exception handling
		
	def create_submodule(self, *args, **kwargs):
		return Submodule.add(self, *args, **kwargs)
		
	def iter_submodules(self, *args, **kwargs):
		return RootModule(self).traverse(*args, **kwargs)
		
	def submodule_update(self, *args, **kwargs):
		return RootModule(self).update(*args, **kwargs)
	
