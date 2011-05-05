# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Module containing information about types known to the database"""

#{ String types 

# For compatability only, use ObjectType instead
str_blob_type = "blob"
str_commit_type = "commit"
str_tree_type = "tree"
str_tag_type = "tag"

class ObjectType(object):
	"""Enumeration providing object types as strings and ids"""
	blob = str_blob_type
	commit = str_commit_type
	tree = str_tree_type
	tag = str_tag_type

	commit_id = 1
	tree_id = 2
	blob_id = 3
	tag_id = 4

#} END string types
