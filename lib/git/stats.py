# stats.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

class Stats(object):
    def __init__(self, repo, total, files):
        self.repo = repo
        self.total = total
        self.files = files

    @classmethod
    def list_from_string(cls, repo, text):
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
