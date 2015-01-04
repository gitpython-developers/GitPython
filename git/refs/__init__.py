
from __future__ import absolute_import
# import all modules in order, fix the names they require
from .symbolic import *
from .reference import *
from .head import *
from .tag import *
from .remote import *

# name fixes
from . import head
head.RemoteReference = RemoteReference
del(head)


from . import symbolic
for item in (HEAD, Head, RemoteReference, TagReference, Reference, SymbolicReference):
    setattr(symbolic, item.__name__, item)
del(symbolic)


from .log import *
