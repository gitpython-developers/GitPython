# base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os

class LazyMixin(object):
    lazy_properties = []
    
    __slots__ = "__baked__"
    
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
    type = None         # to be set by subclass
    
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
    
    @classmethod
    def get_type_by_name(cls, object_type_name):
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
        
        
class Ref(object):
    """
    Represents a named reference to any object
    """
    __slots__ = ("path", "object")
    
    def __init__(self, path, object = None):
        """
        Initialize this instance
        
        ``path``
            Path relative to the .git/ directory pointing to the ref in question, i.e.
            refs/heads/master
            
        ``object``
            Object instance, will be retrieved on demand if None
        """
        self.path = path
        self.object = object
        
    def __str__(self):
    	return self.name()
    	
    def __repr__(self):
    	return '<git.%s "%s">' % (self.__class__.__name__, self.path)
    	
    def __eq__(self, other):
    	return self.path == other.path and self.object == other.object
    	
    def __ne__(self, other):
    	return not ( self == other )
    	
    def __hash__(self):
    	return hash(self.path)
        
    @property
    def name(self):
        """
        Returns
            Name of this reference
        """
        return os.path.basename(self.path)
        
    @classmethod
    def find_all(cls, repo, common_path = "refs", **kwargs):
        """
        Find all refs in the repository

        ``repo``
            is the Repo

        ``common_path``
            Optional keyword argument to the path which is to be shared by all
            returned Ref objects

        ``kwargs``
            Additional options given as keyword arguments, will be passed
            to git-for-each-ref

        Returns
            git.Ref[]
            
            List is sorted by committerdate
            The returned objects are compatible to the Ref base, but represent the 
            actual type, such as Head or Tag
        """

        options = {'sort': "committerdate",
                   'format': "%(refname)%00%(objectname)%00%(objecttype)%00%(objectsize)"}
                   
        options.update(kwargs)

        output = repo.git.for_each_ref(common_path, **options)
        return cls.list_from_string(repo, output)

    @classmethod
    def list_from_string(cls, repo, text):
        """
        Parse out ref information into a list of Ref compatible objects

        ``repo``
            is the Repo
        ``text``
            is the text output from the git-for-each-ref command

        Returns
            git.Ref[]
            
            list of Ref objects
        """
        heads = []

        for line in text.splitlines():
            heads.append(cls.from_string(repo, line))

        return heads

    @classmethod
    def from_string(cls, repo, line):
        """
        Create a new Ref instance from the given string.

        ``repo``
            is the Repo

        ``line``
            is the formatted ref information

        Format::
        
            name: [a-zA-Z_/]+
            <null byte>
            id: [0-9A-Fa-f]{40}

        Returns
            git.Head
        """
        full_path, hexsha, type_name, object_size = line.split("\x00")
        obj = Object.get_type_by_name(type_name)(repo, hexsha, object_size)
        return cls(full_path, obj)
