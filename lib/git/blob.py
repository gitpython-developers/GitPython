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
import base

class Blob(base.Object):
    """A Blob encapsulates a git blob object"""
    DEFAULT_MIME_TYPE = "text/plain"
    type = "blob"
    __slots__ = ("mode", "path", "_data_stored")

    # precompiled regex
    re_whitespace = re.compile(r'\s+')
    re_hexsha_only = re.compile('^[0-9A-Fa-f]{40}$')
    re_author_committer_start = re.compile(r'^(author|committer)')
    re_tab_full_line = re.compile(r'^\t(.*)$')
    
    def __init__(self, repo, id, mode=None, path=None):
        """
        Create an unbaked Blob containing just the specified attributes

        ``repo``
            is the Repo

        ``id``
            is the git object id

        ``mode``
            is the file mode

        ``path``
            is the path to the file

        Returns
            git.Blob
        """
        super(Blob,self).__init__(repo, id, "blob")
        self.mode = mode
        self.path = path
        self._data_stored  = None

    @property
    def data(self):
        """
        The binary contents of this blob.

        Returns
            str
            
        NOTE
            The data will be cached after the first access.
        """
        self._data_stored = self._data_stored or self.repo.git.cat_file(self.id, p=True, with_raw_output=True)
        return self._data_stored

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
        if self.path:
            guesses = mimetypes.guess_type(self.path)
        return guesses and guesses[0] or self.DEFAULT_MIME_TYPE

    @property
    def basename(self):
      """
      Returns
          The basename of the Blobs file path
      """
      return os.path.basename(self.path)

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
            parts = cls.re_whitespace.split(line, 1)
            firstpart = parts[0]
            if cls.re_hexsha_only.search(firstpart):
                # handles 
                # 634396b2f541a9f2d58b00be1a07f0c358b999b3 1 1 7		- indicates blame-data start
                # 634396b2f541a9f2d58b00be1a07f0c358b999b3 2 2
                digits = parts[-1].split(" ")
                if len(digits) == 3:
					info = {'id': firstpart}
					blames.append([None, []])
				# END blame data initialization
            else:
                m = cls.re_author_committer_start.search(firstpart)
                if m:
                    # handles: 
                    # author Tom Preston-Werner
                    # author-mail <tom@mojombo.com>
                    # author-time 1192271832
                    # author-tz -0700
                    # committer Tom Preston-Werner
                    # committer-mail <tom@mojombo.com>
                    # committer-time 1192271832
                    # committer-tz -0700  - IGNORED BY US
                    role = m.group(0)
                    if firstpart.endswith('-mail'):
                        info["%s_email" % role] = parts[-1]
                    elif firstpart.endswith('-time'):
                        info["%s_date" % role] = time.gmtime(int(parts[-1]))
                    elif role == firstpart:
                        info[role] = parts[-1]
                    # END distinguish mail,time,name
                else:
                    # handle
                    # filename lib/grit.rb
                    # summary add Blob
                    # <and rest>
                    if firstpart.startswith('filename'):
                        info['filename'] = parts[-1]
                    elif firstpart.startswith('summary'):
                        info['summary'] = parts[-1]
                    elif firstpart == '':
                        if info:
                            sha = info['id']
                            c = commits.get(sha)
                            if c is None:
                                c = Commit(  repo, id=sha,
                                             author=Actor.from_string(info['author'] + ' ' + info['author_email']),
                                             authored_date=info['author_date'],
                                             committer=Actor.from_string(info['committer'] + ' ' + info['committer_email']),
                                             committed_date=info['committer_date'],
                                             message=info['summary'])
                                commits[sha] = c
                            # END if commit objects needs initial creation
                            m = cls.re_tab_full_line.search(line)
                            text,  = m.groups()
                            blames[-1][0] = c
                            blames[-1][1].append( text )
                            info = None
                        # END if we collected commit info
                    # END distinguish filename,summary,rest
                # END distinguish author|committer vs filename,summary,rest
            # END distinguish hexsha vs other information
        return blames

    def __repr__(self):
        return '<git.Blob "%s">' % self.id
