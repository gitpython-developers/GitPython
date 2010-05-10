# refs.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
""" Module containing all ref based objects """

import os
from objects import Object, Commit
from objects.utils import get_object_type_by_name
from utils import LazyMixin, Iterable, join_path, join_path_native, to_native_path_linux


class SymbolicReference(object):
    """
    Represents a special case of a reference such that this reference is symbolic.
    It does not point to a specific commit, but to another Head, which itself 
    specifies a commit.
    
    A typical example for a symbolic reference is HEAD.
    """
    __slots__ = ("repo", "path")
    _common_path_default = ""
    _id_attribute_ = "name"
    
    def __init__(self, repo, path):
        self.repo = repo
        self.path = path
        
    def __str__(self):
        return self.path
        
    def __repr__(self):
        return '<git.%s "%s">' % (self.__class__.__name__, self.path)
        
    def __eq__(self, other):
        return self.path == other.path
        
    def __ne__(self, other):
        return not ( self == other )
        
    def __hash__(self):
        return hash(self.path)
        
    @property
    def name(self):
        """
        Returns
            In case of symbolic references, the shortest assumable name 
            is the path itself.
        """
        return self.path    
    
    def _get_path(self):
        return join_path_native(self.repo.git_dir, self.path)
        
    @classmethod
    def _get_packed_refs_path(cls, repo):
        return os.path.join(repo.git_dir, 'packed-refs')
        
    @classmethod
    def _iter_packed_refs(cls, repo):
        """Returns an iterator yielding pairs of sha1/path pairs for the corresponding
        refs.
        NOTE: The packed refs file will be kept open as long as we iterate"""
        try:
            fp = open(cls._get_packed_refs_path(repo), 'r')
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('#'):
                    if line.startswith('# pack-refs with:') and not line.endswith('peeled'):
                        raise TypeError("PackingType of packed-Refs not understood: %r" % line)
                    # END abort if we do not understand the packing scheme
                    continue
                # END parse comment
                
                # skip dereferenced tag object entries - previous line was actual
                # tag reference for it
                if line[0] == '^':
                    continue
                
                yield tuple(line.split(' ', 1))
            # END for each line
        except (OSError,IOError):
            raise StopIteration
        # END no packed-refs file handling 
        # NOTE: Had try-finally block around here to close the fp, 
        # but some python version woudn't allow yields within that.
        # I believe files are closing themselves on destruction, so it is 
        # alright.
        
    def _get_ref_info(self):
        """Return: (sha, target_ref_path) if available, the sha the file at 
        rela_path points to, or None. target_ref_path is the reference we 
        point to, or None"""
        tokens = None
        try:
            fp = open(self._get_path(), 'r')
            value = fp.read().rstrip()
            fp.close()
            tokens = value.split(" ")
        except (OSError,IOError):
            # Probably we are just packed, find our entry in the packed refs file
            # NOTE: We are not a symbolic ref if we are in a packed file, as these
            # are excluded explictly
            for sha, path in self._iter_packed_refs(self.repo):
                if path != self.path: continue
                tokens = (sha, path)
                break
            # END for each packed ref
        # END handle packed refs
        
        if tokens is None:
            raise ValueError("Reference at %r does not exist" % self.path)
        
        # is it a reference ?
        if tokens[0] == 'ref:':
            return (None, tokens[1])
            
        # its a commit
        if self.repo.re_hexsha_only.match(tokens[0]):
            return (tokens[0], None)
            
        raise ValueError("Failed to parse reference information from %r" % self.path)
        
    def _get_commit(self):
        """
        Returns:
            Commit object we point to, works for detached and non-detached 
            SymbolicReferences
        """
        # we partially reimplement it to prevent unnecessary file access
        sha, target_ref_path = self._get_ref_info()
        
        # it is a detached reference
        if sha:
            return Commit(self.repo, sha)
        
        return self.from_path(self.repo, target_ref_path).commit
        
    def _set_commit(self, commit):
        """
        Set our commit, possibly dereference our symbolic reference first.
        """
        if self.is_detached:
            return self._set_reference(commit)
            
        # set the commit on our reference
        self._get_reference().commit = commit
    
    commit = property(_get_commit, _set_commit, doc="Query or set commits directly")
        
    def _get_reference(self):
        """
        Returns
            Reference Object we point to
        """
        sha, target_ref_path = self._get_ref_info()
        if target_ref_path is None:
            raise TypeError("%s is a detached symbolic reference as it points to %r" % (self, sha))
        return self.from_path(self.repo, target_ref_path)
        
    def _set_reference(self, ref):
        """
        Set ourselves to the given ref. It will stay a symbol if the ref is a Reference.
        Otherwise we try to get a commit from it using our interface.
        
        Strings are allowed but will be checked to be sure we have a commit
        """
        write_value = None
        if isinstance(ref, SymbolicReference):
            write_value = "ref: %s" % ref.path
        elif isinstance(ref, Commit):
            write_value = ref.sha
        else:
            try:
                write_value = ref.commit.sha
            except AttributeError:
                sha = str(ref)
                try:
                    obj = Object.new(self.repo, sha)
                    if obj.type != "commit":
                        raise TypeError("Invalid object type behind sha: %s" % sha)
                    write_value = obj.sha
                except Exception:
                    raise ValueError("Could not extract object from %s" % ref)
            # END end try string  
        # END try commit attribute
        
        # if we are writing a ref, use symbolic ref to get the reflog and more
        # checking
        # Otherwise we detach it and have to do it manually
        if write_value.startswith('ref:'):
            self.repo.git.symbolic_ref(self.path, write_value[5:])
            return 
        # END non-detached handling
        
        path = self._get_path()
        directory = os.path.dirname(path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        
        fp = open(path, "wb")
        try:
            fp.write(write_value)
        finally:
            fp.close()
        # END writing
        
    reference = property(_get_reference, _set_reference, doc="Returns the Reference we point to")
    
    # alias
    ref = reference
        
    def is_valid(self):
        """
        Returns
            True if the reference is valid, hence it can be read and points to 
            a valid object or reference.
        """
        try:
            self.commit
        except (OSError, ValueError):
            return False
        else:
            return True
        
    @property
    def is_detached(self):
        """
        Returns
            True if we are a detached reference, hence we point to a specific commit
            instead to another reference
        """
        try:
            self.reference
            return False
        except TypeError:
            return True
    

    @classmethod
    def to_full_path(cls, path):
        """:return: string with a full path name which can be used to initialize 
        a Reference instance, for instance by using ``Reference.from_path``"""
        if isinstance(path, SymbolicReference):
            path = path.path
        full_ref_path = path
        if not cls._common_path_default:
            return full_ref_path
        if not path.startswith(cls._common_path_default+"/"):
            full_ref_path = '%s/%s' % (cls._common_path_default, path)
        return full_ref_path
    
    @classmethod
    def delete(cls, repo, path):
        """Delete the reference at the given path
        
        ``repo``
            Repository to delete the reference from
        
        ``path``
            Short or full path pointing to the reference, i.e. refs/myreference
            or just "myreference", hence 'refs/' is implied.
            Alternatively the symbolic reference to be deleted
        """
        full_ref_path = cls.to_full_path(path)
        abs_path = os.path.join(repo.git_dir, full_ref_path)
        if os.path.exists(abs_path):
            os.remove(abs_path)
        else:
            # check packed refs
            pack_file_path = cls._get_packed_refs_path(repo)
            try:
                reader = open(pack_file_path)
            except (OSError,IOError):
                pass # it didnt exist at all
            else:
                new_lines = list()
                made_change = False
                dropped_last_line = False
                for line in reader:
                    # keep line if it is a comment or if the ref to delete is not 
                    # in the line
                    # If we deleted the last line and this one is a tag-reference object, 
                    # we drop it as well
                    if ( line.startswith('#') or full_ref_path not in line ) and \
                        ( not dropped_last_line or dropped_last_line and not line.startswith('^') ):
                        new_lines.append(line)
                        dropped_last_line = False
                        continue
                    # END skip comments and lines without our path
                    
                    # drop this line
                    made_change = True
                    dropped_last_line = True
                # END for each line in packed refs
                reader.close()
                
                # write the new lines
                if made_change:
                    open(pack_file_path, 'w').writelines(new_lines)
            # END open exception handling
        # END handle deletion
            
    @classmethod
    def _create(cls, repo, path, resolve, reference, force):
        """internal method used to create a new symbolic reference.
        If resolve is False,, the reference will be taken as is, creating 
        a proper symbolic reference. Otherwise it will be resolved to the 
        corresponding object and a detached symbolic reference will be created
        instead"""
        full_ref_path = cls.to_full_path(path)
        abs_ref_path = os.path.join(repo.git_dir, full_ref_path)
        
        # figure out target data
        target = reference
        if resolve:
            target = Object.new(repo, reference)
            
        if not force and os.path.isfile(abs_ref_path):
            target_data = str(target)
            if isinstance(target, SymbolicReference):
                target_data = target.path
            if not resolve:
                target_data = "ref: " + target_data
            if open(abs_ref_path, 'rb').read().strip() != target_data:
                raise OSError("Reference at %s does already exist" % full_ref_path)
        # END no force handling
        
        ref = cls(repo, full_ref_path)
        ref.reference = target
        return ref
        
    @classmethod
    def create(cls, repo, path, reference='HEAD', force=False ):
        """
        Create a new symbolic reference, hence a reference pointing to another 
        reference.
        ``repo``
            Repository to create the reference in 
            
        ``path``
            full path at which the new symbolic reference is supposed to be 
            created at, i.e. "NEW_HEAD" or "symrefs/my_new_symref"
            
        ``reference``
            The reference to which the new symbolic reference should point to
        
        ``force``
            if True, force creation even if a symbolic reference with that name already exists.
            Raise OSError otherwise
            
        Returns
            Newly created symbolic Reference
            
        Raises OSError  
            If a (Symbolic)Reference with the same name but different contents
            already exists.
        Note
            This does not alter the current HEAD, index or Working Tree
        """
        return cls._create(repo, path, False, reference, force)
    
    def rename(self, new_path, force=False):
        """
        Rename self to a new path
        
        ``new_path``
            Either a simple name or a full path, i.e. new_name or features/new_name.
            The prefix refs/ is implied for references and will be set as needed.
            In case this is a symbolic ref, there is no implied prefix
            
        ``force``
            If True, the rename will succeed even if a head with the target name
            already exists. It will be overwritten in that case
            
        Returns
            self
            
        Raises OSError:
            In case a file at path but a different contents already exists
        """
        new_path = self.to_full_path(new_path)
        if self.path == new_path:
            return self
        
        new_abs_path = os.path.join(self.repo.git_dir, new_path)
        cur_abs_path = os.path.join(self.repo.git_dir, self.path)
        if os.path.isfile(new_abs_path):
            if not force:
                # if they point to the same file, its not an error
                if open(new_abs_path,'rb').read().strip() != open(cur_abs_path,'rb').read().strip():
                    raise OSError("File at path %r already exists" % new_abs_path)
                # else: we could remove ourselves and use the otherone, but 
                # but clarity we just continue as usual
            # END not force handling
            os.remove(new_abs_path)
        # END handle existing target file
        
        dirname = os.path.dirname(new_abs_path)
        if not os.path.isdir(dirname):
            os.makedirs(dirname)
        # END create directory
        
        os.rename(cur_abs_path, new_abs_path)
        self.path = new_path
        
        return self
        
    @classmethod
    def _iter_items(cls, repo, common_path = None):
        if common_path is None:
            common_path = cls._common_path_default
        rela_paths = set()
        
        # walk loose refs
        # Currently we do not follow links 
        for root, dirs, files in os.walk(join_path_native(repo.git_dir, common_path)):
            if 'refs/' not in root: # skip non-refs subfolders
                refs_id = [ i for i,d in enumerate(dirs) if d == 'refs' ]
                if refs_id:
                    dirs[0:] = ['refs']
            # END prune non-refs folders
            
            for f in files:
                abs_path = to_native_path_linux(join_path(root, f))
                rela_paths.add(abs_path.replace(to_native_path_linux(repo.git_dir) + '/', ""))
            # END for each file in root directory
        # END for each directory to walk
        
        # read packed refs
        for sha, rela_path in cls._iter_packed_refs(repo):
            if rela_path.startswith(common_path):
                rela_paths.add(rela_path)
            # END relative path matches common path
        # END packed refs reading
        
        # return paths in sorted order
        for path in sorted(rela_paths):
            try:
                yield cls.from_path(repo, path)
            except ValueError:
                continue
        # END for each sorted relative refpath
        
    @classmethod
    def iter_items(cls, repo, common_path = None):
        """
        Find all refs in the repository

        ``repo``
            is the Repo

        ``common_path``
            Optional keyword argument to the path which is to be shared by all
            returned Ref objects.
            Defaults to class specific portion if None assuring that only 
            refs suitable for the actual class are returned.

        Returns
            git.SymbolicReference[], each of them is guaranteed to be a symbolic
            ref which is not detached.
            
            List is lexigraphically sorted
            The returned objects represent actual subclasses, such as Head or TagReference
        """
        return ( r for r in cls._iter_items(repo, common_path) if r.__class__ == SymbolicReference or not r.is_detached )
        
    @classmethod
    def from_path(cls, repo, path):
        """
        Return
            Instance of type Reference, Head, or Tag
            depending on the given path
        """
        if not path:
            raise ValueError("Cannot create Reference from %r" % path)
        
        for ref_type in (HEAD, Head, RemoteReference, TagReference, Reference, SymbolicReference):
            try:
                instance = ref_type(repo, path)
                if instance.__class__ == SymbolicReference and instance.is_detached:
                    raise ValueError("SymbolRef was detached, we drop it")
                return instance
            except ValueError:
                pass
            # END exception handling
        # END for each type to try
        raise ValueError("Could not find reference type suitable to handle path %r" % path)
        

class Reference(SymbolicReference, LazyMixin, Iterable):
    """
    Represents a named reference to any object. Subclasses may apply restrictions though, 
    i.e. Heads can only point to commits.
    """
    __slots__ = tuple()
    _common_path_default = "refs"
    
    def __init__(self, repo, path):
        """
        Initialize this instance
        ``repo``
            Our parent repository
        
        ``path``
            Path relative to the .git/ directory pointing to the ref in question, i.e.
            refs/heads/master
            
        """
        if not path.startswith(self._common_path_default+'/'):
            raise ValueError("Cannot instantiate %r from path %s" % ( self.__class__.__name__, path ))
        super(Reference, self).__init__(repo, path)
        

    def __str__(self):
        return self.name

    def _get_object(self):
        """
        Returns
            The object our ref currently refers to. Refs can be cached, they will 
            always point to the actual object as it gets re-created on each query
        """
        # have to be dynamic here as we may be a tag which can point to anything
        # Our path will be resolved to the hexsha which will be used accordingly
        return Object.new(self.repo, self.path)
        
    def _set_object(self, ref):
        """
        Set our reference to point to the given ref. It will be converted
        to a specific hexsha.
        
        Note: 
            TypeChecking is done by the git command
        """
        # do it safely by specifying the old value
        self.repo.git.update_ref(self.path, ref, self._get_object().sha)
        
    object = property(_get_object, _set_object, doc="Return the object our ref currently refers to")
        
    @property
    def name(self):
        """
        Returns
           (shortest) Name of this reference - it may contain path components
        """
        # first two path tokens are can be removed as they are 
        # refs/heads or refs/tags or refs/remotes
        tokens = self.path.split('/')
        if len(tokens) < 3:
            return self.path           # could be refs/HEAD
        return '/'.join(tokens[2:])
    
    
    @classmethod
    def create(cls, repo, path, commit='HEAD', force=False ):
        """
        Create a new reference.
        ``repo``
            Repository to create the reference in 
            
        ``path``
            The relative path of the reference, i.e. 'new_branch' or 
            feature/feature1. The path prefix 'refs/' is implied if not 
            given explicitly
            
        ``commit``
            Commit to which the new reference should point, defaults to the 
            current HEAD
        
        ``force``
            if True, force creation even if a reference with that  name already exists.
            Raise OSError otherwise
            
        Returns
            Newly created Reference
            
        Note
            This does not alter the current HEAD, index or Working Tree
        """
        return cls._create(repo, path, True, commit, force)
    
    @classmethod    
    def iter_items(cls, repo, common_path = None):
        """
        Equivalent to SymbolicReference.iter_items, but will return non-detached
        references as well.
        """
        return cls._iter_items(repo, common_path)
    
    
class HEAD(SymbolicReference):
    """
    Special case of a Symbolic Reference as it represents the repository's 
    HEAD reference.
    """
    _HEAD_NAME = 'HEAD'
    __slots__ = tuple()
    
    def __init__(self, repo, path=_HEAD_NAME):
        if path != self._HEAD_NAME:
            raise ValueError("HEAD instance must point to %r, got %r" % (self._HEAD_NAME, path))
        super(HEAD, self).__init__(repo, path)
    
    
    def reset(self, commit='HEAD', index=True, working_tree = False, 
                paths=None, **kwargs):
        """
        Reset our HEAD to the given commit optionally synchronizing 
        the index and working tree. The reference we refer to will be set to 
        commit as well.
        
        ``commit``
            Commit object, Reference Object or string identifying a revision we 
            should reset HEAD to.
            
        ``index``
            If True, the index will be set to match the given commit. Otherwise
            it will not be touched.
        
        ``working_tree``
            If True, the working tree will be forcefully adjusted to match the given
            commit, possibly overwriting uncommitted changes without warning.
            If working_tree is True, index must be true as well
        
        ``paths``
            Single path or list of paths relative to the git root directory
            that are to be reset. This allow to partially reset individual files.
        
        ``kwargs``
            Additional arguments passed to git-reset. 
        
        Returns
            self
        """
        mode = "--soft"
        if index:
            mode = "--mixed"
            
        if working_tree:
            mode = "--hard"
            if not index:
                raise ValueError( "Cannot reset the working tree if the index is not reset as well") 
        # END working tree handling
        
        self.repo.git.reset(mode, commit, paths, **kwargs)
        
        return self
    

class Head(Reference):
    """
    A Head is a named reference to a Commit. Every Head instance contains a name
    and a Commit object.

    Examples::

        >>> repo = Repo("/path/to/repo")
        >>> head = repo.heads[0]

        >>> head.name       
        'master'

        >>> head.commit     
        <git.Commit "1c09f116cbc2cb4100fb6935bb162daa4723f455">

        >>> head.commit.sha
        '1c09f116cbc2cb4100fb6935bb162daa4723f455'
    """
    _common_path_default = "refs/heads"
    
    @classmethod
    def create(cls, repo, path, commit='HEAD', force=False, **kwargs ):
        """
        Create a new head.
        ``repo``
            Repository to create the head in 
            
        ``path``
            The name or path of the head, i.e. 'new_branch' or 
            feature/feature1. The prefix refs/heads is implied.
            
        ``commit``
            Commit to which the new head should point, defaults to the 
            current HEAD
        
        ``force``
            if True, force creation even if branch with that  name already exists.
            
        ``**kwargs``
            Additional keyword arguments to be passed to git-branch, i.e.
            track, no-track, l
        
        Returns
            Newly created Head
            
        Note
            This does not alter the current HEAD, index or Working Tree
        """
        if cls is not Head:
            raise TypeError("Only Heads can be created explicitly, not objects of type %s" % cls.__name__)
        
        args = ( path, commit )
        if force:
            kwargs['f'] = True
        
        repo.git.branch(*args, **kwargs)
        return cls(repo, "%s/%s" % ( cls._common_path_default, path))
            
        
    @classmethod
    def delete(cls, repo, *heads, **kwargs):
        """
        Delete the given heads
        
        ``force``
            If True, the heads will be deleted even if they are not yet merged into
            the main development stream.
            Default False
        """
        force = kwargs.get("force", False)
        flag = "-d"
        if force:
            flag = "-D"
        repo.git.branch(flag, *heads)
        
    
    def rename(self, new_path, force=False):
        """
        Rename self to a new path
        
        ``new_path``
            Either a simple name or a path, i.e. new_name or features/new_name.
            The prefix refs/heads is implied
            
        ``force``
            If True, the rename will succeed even if a head with the target name
            already exists.
            
        Returns
            self
            
        Note
            respects the ref log as git commands are used
        """
        flag = "-m"
        if force:
            flag = "-M"
            
        self.repo.git.branch(flag, self, new_path)
        self.path  = "%s/%s" % (self._common_path_default, new_path)
        return self
        
    def checkout(self, force=False, **kwargs):
        """
        Checkout this head by setting the HEAD to this reference, by updating the index
        to reflect the tree we point to and by updating the working tree to reflect 
        the latest index.
        
        The command will fail if changed working tree files would be overwritten.
        
        ``force``
            If True, changes to the index and the working tree will be discarded.
            If False, GitCommandError will be raised in that situation.
            
        ``**kwargs``
            Additional keyword arguments to be passed to git checkout, i.e.
            b='new_branch' to create a new branch at the given spot.
        
        Returns
            The active branch after the checkout operation, usually self unless
            a new branch has been created.
        
        Note
            By default it is only allowed to checkout heads - everything else
            will leave the HEAD detached which is allowed and possible, but remains
            a special state that some tools might not be able to handle.
        """
        args = list()
        kwargs['f'] = force
        if kwargs['f'] == False:
            kwargs.pop('f')
        
        self.repo.git.checkout(self, **kwargs)
        return self.repo.active_branch
        

class TagReference(Reference):
    """
    Class representing a lightweight tag reference which either points to a commit 
    ,a tag object or any other object. In the latter case additional information, 
    like the signature or the tag-creator, is available.
    
    This tag object will always point to a commit object, but may carray additional
    information in a tag object::
    
     tagref = TagReference.list_items(repo)[0]
     print tagref.commit.message
     if tagref.tag is not None:
        print tagref.tag.message
    """
    
    __slots__ = tuple()
    _common_path_default = "refs/tags"
    
    @property
    def commit(self):
        """
        Returns
            Commit object the tag ref points to
        """
        if self.object.type == "commit":
            return self.object
        elif self.object.type == "tag":
            # it is a tag object which carries the commit as an object - we can point to anything
            return self.object.object
        else:
            raise ValueError( "Tag %s points to a Blob or Tree - have never seen that before" % self )  

    @property
    def tag(self):
        """
        Returns
            Tag object this tag ref points to or None in case 
            we are a light weight tag
        """
        if self.object.type == "tag":
            return self.object
        return None
        
    @classmethod
    def create(cls, repo, path, ref='HEAD', message=None, force=False, **kwargs):
        """
        Create a new tag reference.
        
        ``path``
            The name of the tag, i.e. 1.0 or releases/1.0. 
            The prefix refs/tags is implied
            
        ``ref``
            A reference to the object you want to tag. It can be a commit, tree or 
            blob.
            
        ``message``
            If not None, the message will be used in your tag object. This will also 
            create an additional tag object that allows to obtain that information, i.e.::
                tagref.tag.message
            
        ``force``
            If True, to force creation of a tag even though that tag already exists.
            
        ``**kwargs``
            Additional keyword arguments to be passed to git-tag
            
        Returns
            A new TagReference
        """
        args = ( path, ref )
        if message:
            kwargs['m'] =  message
        if force:
            kwargs['f'] = True
        
        repo.git.tag(*args, **kwargs)
        return TagReference(repo, "%s/%s" % (cls._common_path_default, path))
        
    @classmethod
    def delete(cls, repo, *tags):
        """
        Delete the given existing tag or tags
        """
        repo.git.tag("-d", *tags)
        
        
        

        
# provide an alias
Tag = TagReference

class RemoteReference(Head):
    """
    Represents a reference pointing to a remote head.
    """
    _common_path_default = "refs/remotes"
    
    @property
    def remote_name(self):
        """
        Returns
            Name of the remote we are a reference of, such as 'origin' for a reference
            named 'origin/master'
        """
        tokens = self.path.split('/')
        # /refs/remotes/<remote name>/<branch_name>
        return tokens[2]
        
    @property
    def remote_head(self):
        """
        Returns
            Name of the remote head itself, i.e. master.
            
        NOTE: The returned name is usually not qualified enough to uniquely identify
        a branch
        """
        tokens = self.path.split('/')
        return '/'.join(tokens[3:])
        
    @classmethod
    def delete(cls, repo, *refs, **kwargs):
        """
        Delete the given remote references.
        
        Note
            kwargs are given for compatability with the base class method as we 
            should not narrow the signature.
        """
        repo.git.branch("-d", "-r", *refs)
        # the official deletion method will ignore remote symbolic refs - these 
        # are generally ignored in the refs/ folder. We don't though 
        # and delete remainders manually
        for ref in refs:
            try:
                os.remove(os.path.join(repo.git_dir, ref.path))
            except OSError:
                pass
        # END for each ref
