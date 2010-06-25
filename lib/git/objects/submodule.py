import base

__all__ = ("Submodule", )

class Submodule(base.IndexObject):
	"""Implements access to a git submodule. They are special in that their sha
	represents a commit in the submodule's repository which is to be checked out
	at the path of this instance. 
	The submodule type does not have a string type associated with it, as it exists
	solely as a marker in the tree and index"""
	
	# this is a bogus type for base class compatability
	type = 'submodule'
	
	# TODO: Add functions to retrieve a repo for the submodule, to allow 
	# its initiailization and handling
