# objects.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
""" Module containing all object based types. """
from git.util import RepoAliasMixin
from gitdb.object.tag import GitDB_TagObject
__all__ = ("TagObject", )

class TagObject(GitDB_TagObject, RepoAliasMixin):
	"""Non-Lightweight tag carrying additional information about an object we are pointing to."""
	__slots__ = tuple()
