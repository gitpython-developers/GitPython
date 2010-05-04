# tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import blob
import base
import binascii
import git.diff as diff
import utils
from git.utils import join_path

def sha_to_hex(sha):
    """Takes a string and returns the hex of the sha within"""
    hexsha = binascii.hexlify(sha)
    assert len(hexsha) == 40, "Incorrect length of sha1 string: %d" % hexsha
    return hexsha


class Tree(base.IndexObject, diff.Diffable, utils.Traversable):
    """
    Tress represent a ordered list of Blobs and other Trees. Hence it can be 
    accessed like a list.
    
    Tree's will cache their contents after first retrieval to improve efficiency.
    
    ``Tree as a list``::
        
        Access a specific blob using the  
        tree['filename'] notation.
        
        You may as well access by index
        blob = tree[0]
        
        
    """
    
    type = "tree"
    __slots__ = "_cache"
    
    # using ascii codes for comparison 
    commit_id = 016     
    blob_id = 010
    symlink_id = 012
    tree_id = 004
    
    
    def __init__(self, repo, sha, mode=0, path=None):
        super(Tree, self).__init__(repo, sha, mode, path)

    @classmethod
    def _get_intermediate_items(cls, index_object):
        if index_object.type == "tree":
            return index_object._cache
        return tuple()


    def _set_cache_(self, attr):
        if attr == "_cache":
            # Set the data when we need it
            self._cache = self._get_tree_cache()
        else:
            super(Tree, self)._set_cache_(attr)

    def _get_tree_cache(self):
        """
        Return
            list(object_instance, ...)
        
        ``treeish``
            sha or ref identifying a tree  
        """
        out = list()
        for obj in self._iter_from_data():
            if obj is not None:
                out.append(obj)
            # END if object was handled
        # END for each line from ls-tree
        return out
        
        
    def _iter_from_data(self):
        """
        Reads the binary non-pretty printed representation of a tree and converts
        it into Blob, Tree or Commit objects.
        
        Note: This method was inspired by the parse_tree method in dulwich.
        
        Returns
            list(IndexObject, ...)
        """
        ord_zero = ord('0')
        data = self.data
        len_data = len(data)
        i = 0
        while i < len_data:
            mode = 0
            
            # read mode
            # Some git versions truncate the leading 0, some don't
            # The type will be extracted from the mode later
            while data[i] != ' ':
                # move existing mode integer up one level being 3 bits
                # and add the actual ordinal value of the character
                mode = (mode << 3) + (ord(data[i]) - ord_zero)
                i += 1
            # END while reading mode
            type_id = mode >> 12 
            
            # byte is space now, skip it
            i += 1
            
            # parse name, it is NULL separated
            
            ns = i
            while data[i] != '\0':
                i += 1
            # END while not reached NULL
            name = data[ns:i]
            path = join_path(self.path, name)
            
            # byte is NULL, get next 20
            i += 1
            sha = data[i:i+20]
            i = i + 20
            
            hexsha = sha_to_hex(sha)
            if type_id == self.blob_id or type_id == self.symlink_id:
                yield blob.Blob(self.repo, hexsha, mode, path)
            elif type_id == self.tree_id:
                yield Tree(self.repo, hexsha, mode, path)
            elif type_id == self.commit_id:
                # submodules 
                yield None
            else:
                raise TypeError( "Unknown type found in tree data %i for path '%s'" % (type_id, path))
        # END for each byte in data stream


    def __div__(self, file):
        """
        Find the named object in this tree's contents

        Examples::

            >>> Repo('/path/to/python-git').tree/'lib'
            <git.Tree "6cc23ee138be09ff8c28b07162720018b244e95e">
            >>> Repo('/path/to/python-git').tree/'README.txt'
            <git.Blob "8b1e02c0fb554eed2ce2ef737a68bb369d7527df">

        Returns
            ``git.Blob`` or ``git.Tree``
        
        Raise 
            KeyError if given file or tree does not exist in tree
        """
        msg = "Blob or Tree named %r not found"
        if '/' in file:
            tree = self
            item = self
            tokens = file.split('/')
            for i,token in enumerate(tokens):
                item = tree[token]
                if item.type == 'tree':
                    tree = item
                else:
                    # safety assertion - blobs are at the end of the path
                    if i != len(tokens)-1:
                        raise KeyError(msg % file)  
                    return item
                # END handle item type
            # END for each token of split path
            if item == self:
                raise KeyError(msg % file)
            return item
        else:
            for obj in self._cache:
                if obj.name == file:
                    return obj
            # END for each obj
            raise KeyError( msg % file )
        # END handle long paths


    def __repr__(self):
        return '<git.Tree "%s">' % self.sha
            
    @property
    def trees(self):
        """
        Returns
            list(Tree, ...) list of trees directly below this tree
        """
        return [ i for i in self if i.type == "tree" ]
        
    @property
    def blobs(self):
        """
        Returns
            list(Blob, ...) list of blobs directly below this tree
        """
        return [ i for i in self if i.type == "blob" ]


    def traverse( self, predicate = lambda i,d: True,
                           prune = lambda i,d: False, depth = -1, branch_first=True,
                           visit_once = False, ignore_self=1 ):
        """For documentation, see utils.Traversable.traverse
        
        Trees are set to visist_once = False to gain more performance in the traversal"""
        return super(Tree, self).traverse(predicate, prune, depth, branch_first, visit_once, ignore_self)

    # List protocol
    def __getslice__(self,i,j):
        return self._cache[i:j]
        
    def __iter__(self):
        return iter(self._cache)
        
    def __len__(self):
        return len(self._cache)
        
    def __getitem__(self,item):
        if isinstance(item, int):
            return self._cache[item]
        
        if isinstance(item, basestring):
            # compatability
            return self.__div__(item)
        # END index is basestring 
        
        raise TypeError( "Invalid index type: %r" % item )
        
        
    def __contains__(self,item):
        if isinstance(item, base.IndexObject):
            return item in self._cache
        
        # compatability
        for obj in self._cache:
            if item == obj.path:
                return True
        # END for each item
        return False
    
    def __reversed__(self):
        return reversed(self._cache)
