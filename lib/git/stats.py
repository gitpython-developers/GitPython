# stats.py
# Copyright (C) 2008-2010 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

class Stats(object):
    """
    Represents stat information as presented by git at the end of a merge. It is
    created from the output of a diff operation.

    ``Example``::

     c = Commit( sha1 )
     s = c.stats
     s.total         # full-stat-dict
     s.files         # dict( filepath : stat-dict )

    ``stat-dict``

    A dictionary with the following keys and values::

      deletions = number of deleted lines as int
      insertions = number of inserted lines as int
      lines = total number of lines changed as int, or deletions + insertions

    ``full-stat-dict``

    In addition to the items in the stat-dict, it features additional information::

     files = number of changed files as int

    """
    def __init__(self, repo, total, files):
        self.repo = repo
        self.total = total
        self.files = files

    @classmethod
    def list_from_string(cls, repo, text):
        """
        Create a Stat object from output retrieved by git-diff.

        Returns
            git.Stat
        """
        hsh = {'total': {'insertions': 0, 'deletions': 0, 'lines': 0, 'files': 0}, 'files': {}}
        for line in text.splitlines():
            (raw_insertions, raw_deletions, filename) = line.split("\t")
            insertions = raw_insertions != '-' and int(raw_insertions) or 0
            deletions = raw_deletions != '-' and int(raw_deletions) or 0
            hsh['total']['insertions'] += insertions
            hsh['total']['deletions'] += deletions
            hsh['total']['lines'] += insertions + deletions
            hsh['total']['files'] += 1
            hsh['files'][filename.strip()] = {'insertions': insertions,
                                              'deletions': deletions,
                                              'lines': insertions + deletions}
        return Stats(repo, hsh['total'], hsh['files'])
