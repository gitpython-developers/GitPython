# __init__.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import git.util

def _init_pool():
	"""Assure the pool is actually threaded"""
	size = 2
	print "Setting ThreadPool to %i" % size
	git.util.pool.set_size(size)

