# __init__.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import inspect

__version__ = 'git'

from git.objects import *
from git.refs import *
from git.actor import Actor
from git.diff import *
from git.errors import InvalidGitRepositoryError, NoSuchPathError, GitCommandError
from git.cmd import Git
from git.repo import Repo
from git.stats import Stats
from git.utils import dashify
from git.utils import touch


__all__ = [ name for name, obj in locals().items()
			if not (name.startswith('_') or inspect.ismodule(obj)) ]
