
# import all modules in order, fix the names they require
from symbolic import *
from reference import *
from head import *
from tag import *
from remote import *

# name fixes
import head
head.RemoteReference = RemoteReference
del(head)


import symbolic
for item in (HEAD, Head, RemoteReference, TagReference, Reference, SymbolicReference):
	setattr(symbolic, item.__name__, item)
del(symbolic)


from log import *
