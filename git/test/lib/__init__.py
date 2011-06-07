# __init__.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import inspect
# TODO: Separate names - they do repeat unfortunately. Also deduplicate it, 
# redesign decorators to support multiple database types in succession.
from base import *

from mock import *
from asserts import *
from helper import *


__all__ = [ name for name, obj in locals().items()
            if not (name.startswith('_') or inspect.ismodule(obj)) ]
