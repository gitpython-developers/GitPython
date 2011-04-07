
# import all modules in order, fix the names they require
from symbolic import *
from reference import *
from head import *
from tag import *
from remote import *

# name fixes
import head
head.Head.RemoteReferenceCls = RemoteReference
del(head)


import symbolic
for item in (HEAD, Head, RemoteReference, TagReference, Reference):
	setattr(symbolic.SymbolicReference, item.__name__+'Cls', item)
del(symbolic)


from log import *
