# tag.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from commit import Commit

class Tag(object):
    def __init__(self, name, commit):
        """
        Initialize a newly instantiated Tag

        ``name``
            is the name of the head

        ``commit``
            is the Commit that the head points to
        """
        self.name = name
        self.commit = commit

    @classmethod
    def find_all(cls, repo, **kwargs):
        """
        Find all Tags in the repository

        ``repo``
            is the Repo

        ``kwargs``
            Additional options given as keyword arguments, will be passed 
            to git-for-each-ref

        Returns
            ``git.Tag[]``
            
            List is sorted by committerdate
        """
        options = {'sort': "committerdate",
                  'format': "%(refname)%00%(objectname)"}
        options.update(**kwargs)

        output = repo.git.for_each_ref("refs/tags", **options)
        return cls.list_from_string(repo, output)

    @classmethod
    def list_from_string(cls, repo, text):
        """
        Parse out tag information into an array of Tag objects

        ``repo``
            is the Repo

        ``text``
            is the text output from the git-for-each command

        Returns
            git.Tag[]
        """
        tags = []
        for line in text.splitlines():
            tags.append(cls.from_string(repo, line))
        return tags

    @classmethod
    def from_string(cls, repo, line):
        """
        Create a new Tag instance from the given string.

        ``repo``
            is the Repo

        ``line``
            is the formatted tag information

        Format::
            
            name: [a-zA-Z_/]+
            <null byte>
            id: [0-9A-Fa-f]{40}
        
        Returns
            git.Tag
        """
        full_name, ids = line.split("\x00")
        name = full_name.split("/")[-1]
        commit = Commit(repo, id=ids)
        return Tag(name, commit)

    def __repr__(self):
        return '<git.Tag "%s">' % self.name
