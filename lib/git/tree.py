# tree.py
# Copyright (C) 2008-2010 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
from lazy import LazyMixin
import blob
import submodule

class Tree(LazyMixin):
    def __init__(self, repo, id, mode=None, name=None, commit_context = '', path = ''):
        LazyMixin.__init__(self)
        self.repo = repo
        self.id = id
        self.mode = mode
        self.name = name
        # commit_context (A string with ID of the commit) is a "crutch" that
        # allows us to look up details for submodules, should we find any in
        # this particular tree.
        # Trees don't have a reference to parent (commit, other tree).
        # They can have infinite amounts of parents.
        # However, we need to know what commit got us to this particular
        # tree if we want to know the URI of the submodule.
        # The commit ID of the repo pointed out by submodule is here, in the tree.
        # However, the only way to know what URI that submodule refers to is
        # to read .gitmodules file that's in the top-most tree of SOME commit.
        # Each commit can have a different version of .gitmodule, but through 
        # tree chain lead to the same Tree instance where the submodule is rooted.
        # 
        # There is a short-cut. If submodule is placed in top-most Tree in a 
        # commit (i.e. submodule's path value is "mysubmodule") the .gitmodules
        # file will be in the same exact tree. YEY! we just read that and know
        # the submodule's URI. Shortcut is gone when submodule is nested in the
        # commit like so: "commonfolder/otherfolder/mysubmodule" In this case,
        # commit's root tree will have "Tree 'commonfolder'" which will have 
        # "Tree "otherfolder", which will have "Submodule 'mysubmodule'"
        # By the time we get to "Tree 'otherfolder'" we don't know where to
        # look for ".gitmodules". This is what commit_context is for.
        # The only way you get a value here if you either set it by hand, or
        # traverse the Tree chain that started with CommitInstance.tree, which
        # populates the context upon Tree instantiation.
        self.commit_context = commit_context
        # path is the friend commit_context. since trees don't have links to
        # parents, we have no clue what the "full local path" of a child
        # submodule would be. Submodules are listed as "name" in trees and
        # as "folder/folder/name" in .gitmodules. path helps us keep up with the
        # the folder changes.
        self.path = path
        self._contents = None

    def __bake__(self):
        # Ensure the treeish references directly a tree
        treeish = self.id
        if not treeish.endswith(':'):
            treeish = treeish + ':'

        # Read the tree contents.
        self._contents = {}
        for line in self.repo.git.ls_tree(self.id).splitlines():
            obj = self.content_from_string(self.repo, line, commit_context = self.commit_context, path = self.path)
            if obj is not None:
                self._contents[obj.name] = obj

    @staticmethod
    def content_from_string(repo, text, commit_context = None, path=''):
        """
        Parse a content item and create the appropriate object

        ``repo``
            is the Repo

         ``text``
            is the single line containing the items data in `git ls-tree` format

        Returns
            ``git.Blob`` or ``git.Tree``
        """
        try:
            mode, typ, id, name = text.expandtabs(1).split(" ", 3)
        except:
            return None

        if typ == "tree":
            return Tree(repo, id=id, mode=mode, name=name,
                        commit_context = commit_context, path='/'.join([path,name]))
        elif typ == "blob":
            return blob.Blob(repo, id=id, mode=mode, name=name)
        elif typ == "commit" and mode == '160000':
            return submodule.Submodule(repo, id=id, name=name,
                        commit_context = commit_context, path='/'.join([path,name]))
        else:
          raise(TypeError, "Invalid type: %s" % typ)

    def __div__(self, file):
        """
        Find the named object in this tree's contents

        Examples::

            >>> Repo('/path/to/python-git').tree()/'lib'
            <git.Tree "6cc23ee138be09ff8c28b07162720018b244e95e">
            >>> Repo('/path/to/python-git').tree()/'README'
            <git.Blob "8b1e02c0fb554eed2ce2ef737a68bb369d7527df">

        Returns
            ``git.Blob`` or ``git.Tree`` or ``None`` if not found
        """
        return self.get(file)

    @property
    def basename(self):
        os.path.basename(self.name)

    def __repr__(self):
        return '<git.Tree "%s">' % self.id

    # Implement the basics of the dict protocol:
    # directories/trees can be seen as object dicts.
    def __getitem__(self, key):
        return self._contents[key]

    def __iter__(self):
        return iter(self._contents)

    def __len__(self):
        return len(self._contents)

    def __contains__(self, key):
        return key in self._contents

    def get(self, key):
        return self._contents.get(key)

    def items(self):
        return self._contents.items()

    def keys(self):
        return self._contents.keys()

    def values(self):
        return self._contents.values()
