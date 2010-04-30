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
_re_actor_epoch = re.compile(r'^.+? (.*) (\d+) ([+-]\d+).*$')

def parse_actor_and_date(line):
    """
    Parse out the actor (author or committer) info from a line like::
    
     author Tom Preston-Werner <tom@mojombo.com> 1191999972 -0700
    
    Returns
        [Actor, int_seconds_since_epoch, int_timezone_offset]
    """
    m = _re_actor_epoch.search(line)
    actor, epoch, offset = m.groups()
    return (Actor._from_string(actor), int(epoch), -int(float(offset)/100*3600))
    
    
    
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
            
    
    def traverse( self, predicate = lambda i,d: True,
                           prune = lambda i,d: False, depth = -1, branch_first=True,
                           visit_once = True, ignore_self=1, as_edge = False ):
        """
        ``Returns``
            iterator yieling of items found when traversing self
            
        ``predicate``
            f(i,d) returns False if item i at depth d should not be included in the result
            
        ``prune``
            f(i,d) return True if the search should stop at item i at depth d.
            Item i will not be returned.
            
        ``depth``
            define at which level the iteration should not go deeper
            if -1, there is no limit
            if 0, you would effectively only get self, the root of the iteration
            i.e. if 1, you would only get the first level of predessessors/successors
            
        ``branch_first``
            if True, items will be returned branch first, otherwise depth first
            
        ``visit_once``
            if True, items will only be returned once, although they might be encountered
            several times. Loops are prevented that way.
        
        ``ignore_self``
            if True, self will be ignored and automatically pruned from
            the result. Otherwise it will be the first item to be returned.
            If as_edge is True, the source of the first edge is None
            
        ``as_edge``
            if True, return a pair of items, first being the source, second the 
            destinatination, i.e. tuple(src, dest) with the edge spanning from 
            source to destination"""
        visited = set()
        stack = Deque()
        stack.append( ( 0 ,self, None ) )       # self is always depth level 0
    
        def addToStack( stack, item, branch_first, depth ):
            lst = self._get_intermediate_items( item )
            if not lst:
                return
            if branch_first:
                stack.extendleft( ( depth , i, item ) for i in lst )
            else:
                reviter = ( ( depth , lst[i], item ) for i in range( len( lst )-1,-1,-1) )
                stack.extend( reviter )
        # END addToStack local method
    
        while stack:
            d, item, src = stack.pop()          # depth of item, item, item_source
            
            if visit_once and item in visited:
                continue
                
            if visit_once:
                visited.add(item)
            
            rval = ( as_edge and (src, item) ) or item
            if prune( rval, d ):
                continue
    
            skipStartItem = ignore_self and ( item == self )
            if not skipStartItem and predicate( rval, d ):
                yield rval
    
            # only continue to next level if this is appropriate !
            nd = d + 1
            if depth > -1 and nd > depth:
                continue
    
            addToStack( stack, item, branch_first, nd )
        # END for each item on work stack
