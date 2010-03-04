# base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os
from git.utils import LazyMixin, join_path_native
import utils
    
_assertion_msg_format = "Created object %r whose python type %r disagrees with the acutal git object type %r"

class Object(LazyMixin):
    """
    Implements an Object which may be Blobs, Trees, Commits and Tags
    
    This Object also serves as a constructor for instances of the correct type::
    
        inst = Object.new(repo,id)
        inst.sha        # objects sha in hex
        inst.size   # objects uncompressed data size
        inst.data   # byte string containing the whole data of the object
    """
    NULL_HEX_SHA = '0'*40
    TYPES = ("blob", "tree", "commit", "tag")
    __slots__ = ("repo", "sha", "size", "data" )
    type = None         # to be set by subclass
    
    def __init__(self, repo, id):
        """
        Initialize an object by identifying it by its id. All keyword arguments
        will be set on demand if None.
        
        ``repo``
            repository this object is located in
            
        ``id``
            SHA1 or ref suitable for git-rev-parse
        """
        super(Object,self).__init__()
        self.repo = repo
        self.sha = id

    @classmethod
    def new(cls, repo, id):
        """
        Return
            New Object instance of a type appropriate to the object type behind 
            id. The id of the newly created object will be a hexsha even though 
            the input id may have been a Reference or Rev-Spec
            
        Note
            This cannot be a __new__ method as it would always call __init__
            with the input id which is not necessarily a hexsha.
        """
        hexsha, typename, size = repo.git.get_object_header(id)
        obj_type = utils.get_object_type_by_name(typename)
        inst = obj_type(repo, hexsha)
        inst.size = size
        return inst
    
    def _set_self_from_args_(self, args_dict):
        """
        Initialize attributes on self from the given dict that was retrieved
        from locals() in the calling method.
        
        Will only set an attribute on self if the corresponding value in args_dict
        is not None
        """
        for attr, val in args_dict.items():
            if attr != "self" and val is not None:
                setattr( self, attr, val )
        # END set all non-None attributes
    
    def _set_cache_(self, attr):
        """
        Retrieve object information
        """
        if attr  == "size":
            hexsha, typename, self.size = self.repo.git.get_object_header(self.sha)
            assert typename == self.type, _assertion_msg_format % (self.sha, typename, self.type)
        elif attr == "data":
            hexsha, typename, self.size, self.data = self.repo.git.get_object_data(self.sha)
            assert typename == self.type, _assertion_msg_format % (self.sha, typename, self.type)
        else:
            super(Object,self)._set_cache_(attr)
        
    def __eq__(self, other):
        """
        Returns
            True if the objects have the same SHA1
        """
        return self.sha == other.sha
        
    def __ne__(self, other):
        """
        Returns
            True if the objects do not have the same SHA1
        """
        return self.sha != other.sha
        
    def __hash__(self):
        """
        Returns
            Hash of our id allowing objects to be used in dicts and sets
        """
        return hash(self.sha)
        
    def __str__(self):
        """
        Returns
            string of our SHA1 as understood by all git commands
        """
        return self.sha
        
    def __repr__(self):
        """
        Returns
            string with pythonic representation of our object
        """
        return '<git.%s "%s">' % (self.__class__.__name__, self.sha)

    @property
    def data_stream(self):
        """
        Returns 
            File Object compatible stream to the uncompressed raw data of the object
        """
        proc = self.repo.git.cat_file(self.type, self.sha, as_process=True)
        return utils.ProcessStreamAdapter(proc, "stdout") 

    def stream_data(self, ostream):
        """
        Writes our data directly to the given output stream
        
        ``ostream``
            File object compatible stream object.
            
        Returns
            self
        """
        self.repo.git.cat_file(self.type, self.sha, output_stream=ostream)
        return self

class IndexObject(Object):
    """
    Base for all objects that can be part of the index file , namely Tree, Blob and
    SubModule objects
    """
    __slots__ = ("path", "mode") 
    
    def __init__(self, repo, sha, mode=None, path=None):
        """
        Initialize a newly instanced IndexObject
        ``repo``
            is the Repo we are located in

        ``sha`` : string
            is the git object id as hex sha

        ``mode`` : int
            is the file mode as int, use the stat module to evaluate the infomration

        ``path`` : str
            is the path to the file in the file system, relative to the git repository root, i.e.
            file.ext or folder/other.ext
                
        NOTE
            Path may not be set of the index object has been created directly as it cannot
            be retrieved without knowing the parent tree.
        """
        super(IndexObject, self).__init__(repo, sha)
        self._set_self_from_args_(locals())
        if isinstance(mode, basestring):
            self.mode = self._mode_str_to_int(mode)
    
    def __hash__(self):
        """
        Returns
            Hash of our path as index items are uniquely identifyable by path, not 
            by their data !
        """
        return hash(self.path)
    
    def _set_cache_(self, attr):
        if attr in IndexObject.__slots__:
            # they cannot be retrieved lateron ( not without searching for them )
            raise AttributeError( "path and mode attributes must have been set during %s object creation" % type(self).__name__ )
        else:
            super(IndexObject, self)._set_cache_(attr)
    
    @classmethod
    def _mode_str_to_int(cls, modestr):
        """
        ``modestr``
            string like 755 or 644 or 100644 - only the last 6 chars will be used
            
        Returns
            String identifying a mode compatible to the mode methods ids of the 
            stat module regarding the rwx permissions for user, group and other, 
            special flags and file system flags, i.e. whether it is a symlink
            for example.
        """
        mode = 0
        for iteration,char in enumerate(reversed(modestr[-6:])):
            mode += int(char) << iteration*3
        # END for each char
        return mode
        
    @property
    def name(self):
        """
        Returns
            Name portion of the path, effectively being the basename
        """
        return os.path.basename(self.path)
        
    @property
    def abspath(self):
        """
        Returns
            Absolute path to this index object in the file system ( as opposed to the 
            .path field which is a path relative to the git repository ).
            
            The returned path will be native to the system and contains '\' on windows. 
        """
        return join_path_native(self.repo.working_tree_dir, self.path)
        
