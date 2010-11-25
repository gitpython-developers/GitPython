"""
Import all submodules main classes into the package space
"""
import inspect
from base import *
# Fix import dependency - add IndexObject to the util module, so that it can be 
# imported by the submodule.base
import submodule.util
submodule.util.IndexObject = IndexObject
submodule.util.Object = Object
from submodule.base import *
from submodule.root import *

# must come after submodule was made available
from tag import *
from blob import *
from commit import *
from tree import *

__all__ = [ name for name, obj in locals().items()
            if not (name.startswith('_') or inspect.ismodule(obj)) ]