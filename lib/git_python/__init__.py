import inspect

from git_python.actor import Actor
from git_python.blob import Blob
from git_python.commit import Commit
from git_python.diff import Diff
from git_python.errors import InvalidGitRepositoryError, NoSuchPathError
from git_python.git import Git
from git_python.head import Head
from git_python.repo import Repo
from git_python.stats import Stats
from git_python.tag import Tag
from git_python.tree import Tree
from git_python.utils import dashify
from git_python.utils import touch
from git_python.utils import pop_key

__all__ = [ name for name, obj in locals().items()
            if not (name.startswith('_') or inspect.ismodule(obj)) ]

__version__ = 'svn'
