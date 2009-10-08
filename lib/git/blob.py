# blob.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import mimetypes
import os
import re
import time
from actor import Actor
from commit import Commit

class Blob(object):
    """A Blob encapsulates a git blob object"""
    DEFAULT_MIME_TYPE = "text/plain"

    def __init__(self, repo, id, mode=None, name=None):
        """
        Create an unbaked Blob containing just the specified attributes

        ``repo``
            is the Repo

        ``id``
            is the git object id

        ``mode``
            is the file mode

        ``name``
            is the file name

        Returns
            git.Blob
        """
        self.repo = repo
        self.id = id
        self.mode = mode
        self.name = name

        self._size = None
        self.data_stored  = None

    @property
    def size(self):
        """
        The size of this blob in bytes

        Returns
            int
           
        NOTE
            The size will be cached after the first access
        """
        if self._size is None:
            self._size = int(self.repo.git.cat_file(self.id, s=True).rstrip())
        return self._size

    @property
    def data(self):
        """
        The binary contents of this blob.

        Returns
            str
            
        NOTE
            The data will be cached after the first access.
        """
        self.data_stored = self.data_stored or self.repo.git.cat_file(self.id, p=True, with_raw_output=True)
        return self.data_stored

    @property
    def mime_type(self):
        """
        The mime type of this file (based on the filename)

        Returns
            str
            
        NOTE
            Defaults to 'text/plain' in case the actual file type is unknown.
        """
        guesses = None
        if self.name:
            guesses = mimetypes.guess_type(self.name)
        return guesses and guesses[0] or self.DEFAULT_MIME_TYPE

    @property
    def basename(self):
      """
      Returns
          The basename of the Blobs file name
      """
      return os.path.basename(self.name)

    @classmethod
    def blame(cls, repo, commit, file):
        """
        The blame information for the given file at the given commit

        Returns
            list: [git.Commit, list: [<line>]]
            A list of tuples associating a Commit object with a list of lines that 
            changed within the given commit. The Commit objects will be given in order
            of appearance.
        """
        data = repo.git.blame(commit, '--', file, p=True)
        commits = {}
        blames = []
        info = None

        for line in data.splitlines():
            parts = re.split(r'\s+', line, 1)
            if re.search(r'^[0-9A-Fa-f]{40}$', parts[0]):
                if re.search(r'^([0-9A-Fa-f]{40}) (\d+) (\d+) (\d+)$', line):
                    m = re.search(r'^([0-9A-Fa-f]{40}) (\d+) (\d+) (\d+)$', line)
                    id, origin_line, final_line, group_lines = m.groups()
                    info = {'id': id}
                    blames.append([None, []])
                elif re.search(r'^([0-9A-Fa-f]{40}) (\d+) (\d+)$', line):
                    m = re.search(r'^([0-9A-Fa-f]{40}) (\d+) (\d+)$', line)
                    id, origin_line, final_line = m.groups()
                    info = {'id': id}
            elif re.search(r'^(author|committer)', parts[0]):
                if re.search(r'^(.+)-mail$', parts[0]):
                    m = re.search(r'^(.+)-mail$', parts[0])
                    info["%s_email" % m.groups()[0]] = parts[-1]
                elif re.search(r'^(.+)-time$', parts[0]):
                    m = re.search(r'^(.+)-time$', parts[0])
                    info["%s_date" % m.groups()[0]] = time.gmtime(int(parts[-1]))
                elif re.search(r'^(author|committer)$', parts[0]):
                    m = re.search(r'^(author|committer)$', parts[0])
                    info[m.groups()[0]] = parts[-1]
            elif re.search(r'^filename', parts[0]):
                info['filename'] = parts[-1]
            elif re.search(r'^summary', parts[0]):
                info['summary'] = parts[-1]
            elif parts[0] == '':
                if info:
                    c = commits.has_key(info['id']) and commits[info['id']]
                    if not c:
                        c = Commit(repo, id=info['id'],
                                         author=Actor.from_string(info['author'] + ' ' + info['author_email']),
                                         authored_date=info['author_date'],
                                         committer=Actor.from_string(info['committer'] + ' ' + info['committer_email']),
                                         committed_date=info['committer_date'],
                                         message=info['summary'])
                        commits[info['id']] = c

                    m = re.search(r'^\t(.*)$', line)
                    text,  = m.groups()
                    blames[-1][0] = c
                    blames[-1][1].append( text )
                    info = None

        return blames

    def __repr__(self):
        return '<git.Blob "%s">' % self.id
