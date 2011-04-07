# blob.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.util import RepoAliasMixin
from gitdb.object.blob import Blob as GitDB_Blob

__all__ = ('Blob', )

class Blob(GitDB_Blob, RepoAliasMixin):
	__slots__ = tuple()
