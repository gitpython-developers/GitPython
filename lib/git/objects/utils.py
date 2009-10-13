# util.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module for general utility functions
"""
import commit, tag, blob, tree

def get_object_type_by_name(object_type_name):
	"""
	Returns
		type suitable to handle the given object type name.
		Use the type to create new instances.
		
	``object_type_name``
		Member of TYPES
		
	Raises
		ValueError: In case object_type_name is unknown
	"""
	if object_type_name == "commit":
		import commit
		return commit.Commit
	elif object_type_name == "tag":
		import tag
		return tag.TagObject
	elif object_type_name == "blob":
		import blob
		return blob.Blob
	elif object_type_name == "tree":
		import tree
		return tree.Tree
	else:
		raise ValueError("Cannot handle unknown object type: %s" % object_type_name)
