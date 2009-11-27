# util.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module for general utility functions
"""
import re
from collections import deque as Deque
from git.actor import Actor

def get_object_type_by_name(object_type_name):
	"""
	Returns
		type suitable to handle the given object type name.
		Use the type to create new instances.
		
	``object_type_name``
		Member of TYPES
		
	Raises
		ValueError: In case object_type_name is unknown
	"""
	if object_type_name == "commit":
		import commit
		return commit.Commit
	elif object_type_name == "tag":
		import tag
		return tag.TagObject
	elif object_type_name == "blob":
		import blob
		return blob.Blob
	elif object_type_name == "tree":
		import tree
		return tree.Tree
	else:
		raise ValueError("Cannot handle unknown object type: %s" % object_type_name)
		
	
# precompiled regex
_re_actor_epoch = re.compile(r'^.+? (.*) (\d+) .*$')

def parse_actor_and_date(line):
	"""
	Parse out the actor (author or committer) info from a line like::
	
	 author Tom Preston-Werner <tom@mojombo.com> 1191999972 -0700
	
	Returns
		[Actor, int_seconds_since_epoch]
	"""
	m = _re_actor_epoch.search(line)
	actor, epoch = m.groups()
	return (Actor._from_string(actor), int(epoch))
	
	
	
class ProcessStreamAdapter(object):
	"""
	Class wireing all calls to the contained Process instance.
	
	Use this type to hide the underlying process to provide access only to a specified 
	stream. The process is usually wrapped into an AutoInterrupt class to kill 
	it if the instance goes out of scope.
	"""
	__slots__ = ("_proc", "_stream")
	def __init__(self, process, stream_name):
		self._proc = process
		self._stream = getattr(process, stream_name)
	
	def __getattr__(self, attr):
		return getattr(self._stream, attr)
		
		
class Traversable(object):
	"""Simple interface to perforam depth-first or breadth-first traversals 
	into one direction.
	Subclasses only need to implement one function.
	Instances of the Subclass must be hashable"""
	__slots__ = tuple()
	
	@classmethod
	def _get_intermediate_items(cls, item):
		"""
		Returns:
			List of items connected to the given item.
			Must be implemented in subclass
		"""
		raise NotImplementedError("To be implemented in subclass")
			
	
	def traverse( self, predicate = lambda i: True,
						   prune = lambda i: False, depth = -1, branch_first=True,
						   visit_once = True, ignore_self=1 ):
		"""
		``Returns``
			iterator yieling of items found when traversing self
			
		``predicate``
			f(i) returns False if item i should not be included in the result
			
		``prune``
			f(i) return True if the search should stop at item i.
			Item i will not be returned.
			
		``depth``
			define at which level the iteration should not go deeper
			if -1, there is no limit
			if 0, you would effectively only get self, the root of the iteration
			i.e. if 1, you would only get the first level of predessessors/successors
			
		``branch_first``
			if True, items will be returned branch first, otherwise depth first
			
		``ignore_self``
			if True, self will be ignored and automatically pruned from
			the result. Otherwise it will be the first item to be returned"""
		stack = Deque()
		stack.append( ( 0 ,self ) )		# self is always depth level 0
	
		def addToStack( stack, lst, branch_first, dpth ):
			if not lst:
				return
			if branch_first:
				stack.extendleft( ( dpth , item ) for item in lst )
			else:
				reviter = ( ( dpth , lst[i] ) for i in range( len( lst )-1,-1,-1) )
				stack.extend( reviter )
		# END addToStack local method
	
		while stack:
			d, item = stack.pop()			# depth of item, item
			
			if prune( item ):
				continue
	
			skipStartItem = ignore_self and ( item == self )
			if not skipStartItem and predicate( item ):
				yield item
	
			# only continue to next level if this is appropriate !
			nd = d + 1
			if depth > -1 and nd > depth:
				continue
	
			addToStack( stack, self._get_intermediate_items( item ), branch_first, nd )
		# END for each item on work stack
