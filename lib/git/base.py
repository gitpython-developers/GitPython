# base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

class LazyMixin(object):
    lazy_properties = []

    def __init__(self):
        self.__baked__ = False

    def __getattribute__(self, attr):
        val = object.__getattribute__(self, attr)
        if val is not None:
            return val
        else:
            self.__prebake__()
            return object.__getattribute__(self, attr)

    def __bake__(self):
        """ This method should be overridden in the derived class. """
        raise NotImplementedError(" '__bake__' method has not been implemented.")

    def __prebake__(self):
        if self.__baked__:
            return
        self.__bake__()
        self.__baked__ = True

    def __bake_it__(self):
        self.__baked__ = True
        
        
class Object(LazyMixin):
    """
    Implements an Object which may be Blobs, Trees, Commits and Tags
    """
    TYPES = ("blob", "tree", "commit", "tag")
    __slots__ = ("repo", "id", "size")
    type = None			# to be set by subclass
    
    def __init__(self, repo, id, size=None):
        """
        Initialize an object by identifying it by its id. All keyword arguments
        will be set on demand if None.
        
        ``repo``
        	repository this object is located in
        ``id``
            SHA1 or ref suitable for git-rev-parse
        ``size``
            Size of the object's data in bytes
        """
        super(Object,self).__init__()
        self.repo = repo
        self.id = id
        self.size = size
        
    def __bake__(self):
        """
        Retrieve object information
        """
        self.size = int(self.repo.git.cat_file(self.id, s=True).rstrip())
        
    def __eq__(self, other):
        """
        Returns
            True if the objects have the same SHA1
        """
        return self.id == other.id
        
    def __ne__(self, other):
        """
        Returns
            True if the objects do not have the same SHA1
        """
        return self.id != other.id
        
    def __hash__(self):
        """
        Returns
            Hash of our id allowing objects to be used in dicts and sets
        """
        return hash(self.id)
        
    def __str__(self):
        """
        Returns
            string of our SHA1 as understood by all git commands
        """
        return self.id
        
    def __repr__(self):
        """
        Returns
            string with pythonic representation of our object
        """
        return '<git.%s "%s">' % (self.__class__.__name__, self.id)
