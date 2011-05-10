# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Module providing adaptors to maintain backwards compatability"""

class RepoCompatInterface(object):
	"""Interface to install backwards compatability of the new complex repository
	types with the previous, all in one, repository."""
	
	@property
	def bare(self):
		return self.is_bare
