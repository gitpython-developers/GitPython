# head.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import commit

class Head(object):
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

    def __init__(self, name, commit):
        """
        Initialize a newly instanced Head

        `name`
            is the name of the head

        `commit`
            is the Commit object that the head points to
        """
        self.name = name
        self.commit = commit

    @classmethod
    def find_all(cls, repo, **kwargs):
        """
        Find all Heads in the repository

        `repo`
            is the Repo

        `kwargs`
            Additional options given as keyword arguments, will be passed
            to git-for-each-ref

        Returns
            git.Head[]
            
            List is sorted by committerdate
        """

        options = {'sort': "committerdate",
                   'format': "%(refname)%00%(objectname)"}
        options.update(kwargs)

        output = repo.git.for_each_ref("refs/heads", **options)
        return cls.list_from_string(repo, output)

    @classmethod
    def list_from_string(cls, repo, text):
        """
        Parse out head information into a list of head objects

        ``repo``
            is the Repo
        ``text``
            is the text output from the git-for-each-ref command

        Returns
            git.Head[]
        """
        heads = []

        for line in text.splitlines():
            heads.append(cls.from_string(repo, line))

        return heads

    @classmethod
    def from_string(cls, repo, line):
        """
        Create a new Head instance from the given string.

        ``repo``
            is the Repo

        ``line``
            is the formatted head information

        Format::
        
            name: [a-zA-Z_/]+
            <null byte>
            id: [0-9A-Fa-f]{40}

        Returns
            git.Head
        """
        full_name, ids = line.split("\x00")

        if full_name.startswith('refs/heads/'):
            name = full_name[len('refs/heads/'):]
        else:
            name = full_name

        c = commit.Commit(repo, id=ids)
        return Head(name, c)

    def __repr__(self):
        return '<git.Head "%s">' % self.name
