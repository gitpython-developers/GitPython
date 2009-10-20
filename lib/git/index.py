# index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing Index implementation, allowing to perform all kinds of index
manipulations such as querying and merging.
"""

class Index(object):
	"""
	Implements an Index that can be manipulated using a native implementation in 
	order to safe git command function calls wherever possible.
	
	It provides custom merging facilities and to create custom commits.
	"""
