# __init__.py
# Copyright (C) 2008-2010 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import inspect

__version__ = 'git'

from git.actor import Actor
from git.blob import Blob
from git.commit import Commit
from git.diff import Diff
from git.errors import InvalidGitRepositoryError, NoSuchPathError, GitCommandError
from git.cmd import Git
from git.head import Head
from git.repo import Repo
from git.stats import Stats
from git.tag import Tag
from git.tree import Tree
from git.utils import dashify
from git.utils import touch

__all__ = [ name for name, obj in locals().items()
            if not (name.startswith('_') or inspect.ismodule(obj)) ]
