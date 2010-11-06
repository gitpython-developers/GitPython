# head.py
# Copyright (C) 2008-2010 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re

class Submodule(object):
    """
    A Submodule is a named reference to a Commit on another Repo.
    Every Submodule instance contains a name, a path into the local repo,
    and a URI pointing at the remote repository.

    Submodules are very close in behavior to HEAD pointer. It just sits on
    top of a structure, in this case, at the end of folders tree, and says
    something about that ending.

    Examples::
        >>> repo = Repo("/path/to/repo")
        >>> s = repo.commit('master').tree['lib']['mysubmodule_folder']
        >>> s.name
        'mysubmodule_folder'
        >>> s.path
        '/lib/mysubmodule_folder'
        >>> s.url
        'http://example.com/path/to/repo.git'
        >>> s.id
        "1c09f116cbc2cb4100fb6935bb162daa4723f455"
    """

    def __init__(self, repo=None, id=None, mode=None, name='',
                 commit_context='', path=''):
        """
        Initialize a newly instanced Submodule

        'repo'
            Pointer to Repo object instance.
        'id'
            Is the Sha of the commit on a remote server. This object does NOT
            (usually) exist in this repo.
        'mode'
            A black hole at this time. Trying to keep the input args
            similar between Tree, Blob and Submodule classes.
        'name'
            This is just the last segment in the submodule's full local path.
            It's the name of the actual folder to which a submodule is tied.
        'mode'
            A black hole at this time. Trying to keep the input args
            similar between Tree, Blob and Submodule classes.
        'commit_context'
            A string with ID of the commit that was the root for the tree
            structure that lead us to this folder (Tree object) that contains
            this submodule reference.
            See comments in Tree object code for background.
        'path'
            This is the "longer" version of "name" argument. It includes all
            the parent folders we passed on the way from root of the commit to
            this point in the folder tree.
            Submodules in the .gitmodules are referenced by their full path
            and the contents of this argument is used to retrieve the URI of the
            remote repo tied to this full local path.
            Example: "lib/vendor/vendors_repoA"
        """
        self.repo = repo
        self.id = id
        self.path = path
        self.name = name
        self._commit_context = commit_context
        self._cached_URI = None

    def getURI(self, commit_context = None):
        '''Returns the remote repo URI for the submodule.
        
        This data is NOT stored in the blob or anywhere close. It's in a 
        .gitmodules file in the root Tree of SOME commit.
        
        We need to know what commit to look into to look for .gitmodules.
        
        We try to retain the "origin" commit ID within the object when we
        traverse the Tree chain if it started with a particular commit.
        
        When this does not work, or if you want to override the behavior,
        pass the string with commit's ID to the commit_context argument.
        '''
        if not self._cached_URI and ( commit_context or self._commit_context ):
            _b = self.repo.commit(commit_context or self._commit_context).tree.get('.gitmodules')
            if _b:
                _m = re.findall(
                    r'\[submodule "[^\t]+?\s+path\s*=\s*([^\t]+)\s+url\s*=\s*([^\t]+)'
                    ,'\t'.join(_b.data.splitlines())
                )
                for _e in _m:
                    if _e[0] == self.path.strip('/'):
                        self._cached_URI = _e[1].strip().strip('"').strip("'")
                        break
        return self._cached_URI

    @property
    def url(self):
        return self.getURI()

    def __repr__(self):
        return '<git.Submodule "%s">' % self.id
