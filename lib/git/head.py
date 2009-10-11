# head.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import commit
import base

class Head(base.Ref):
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

        >>> head.commit.id
        '1c09f116cbc2cb4100fb6935bb162daa4723f455'
    """

    def __init__(self, path, commit):
        """
        Initialize a newly instanced Head

        ``path``
            is the path to the head ref, relative to the .git directory, i.e.
            refs/heads/master

        `commit`
            is the Commit object that the head points to
        """
        super(Head, self).__init__(name, commit)


    @property
    def commit(self):
        """
        Returns
            Commit object the head points to
        """
        return self.object
        
    @classmethod
    def find_all(cls, repo, common_path = "refs/heads", **kwargs):
        """
        Returns
            git.Head[]
            
        For more documentation, please refer to git.base.Ref.find_all
        """
        return super(Head,cls).find_all(repo, common_path, **kwargs)

    def __repr__(self):
        return '<git.Head "%s">' % self.name
