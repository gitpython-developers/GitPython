"""
Import all submodules main classes into the package space
"""
import inspect
from git.base import *
# Fix import dependency - add IndexObject to the util module, so that it can be
# imported by the submodule.base
import git.submodule.util
submodule.util.IndexObject = IndexObject
submodule.util.Object = Object
from submodule.base import *
from submodule.root import *

# must come after submodule was made available
from git.tag import *
from git.blob import *
from git.commit import *
from git.tree import *

__all__ = [name for name, obj in locals().items()
           if not (name.startswith('_') or inspect.ismodule(obj))]
