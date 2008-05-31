import os
import inspect

# grab the version information
v = open(os.path.join(os.path.dirname(__file__), '..', '..', 'VERSION'))
__version__ = v.readline().strip()
v.close()

from git.actor import Actor
from git.blob import Blob
from git.commit import Commit
from git.diff import Diff
from git.errors import InvalidGitRepositoryError, NoSuchPathError, GitCommandError
from git.gitter import Git
from git.head import Head
from git.repo import Repo
from git.stats import Stats
from git.tag import Tag
from git.tree import Tree
from git.utils import dashify
from git.utils import touch

__all__ = [ name for name, obj in locals().items()
            if not (name.startswith('_') or inspect.ismodule(obj)) ]
