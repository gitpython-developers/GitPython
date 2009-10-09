# diff.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re
import blob

class Diff(object):
    """
    A Diff contains diff information between two commits.
    
    It contains two sides a and b of the diff, members are prefixed with 
    "a" and "b" respectively to inidcate that.
    
    Diffs keep information about the changed blob objects, the file mode, renames, 
    deletions and new files.
    
    There are a few cases where None has to be expected as member variable value:
    
    ``New File``::
    
        a_mode is None
        a_blob is None
        
    ``Deleted File``::
    
        b_mode is None
        b_blob is NOne
    """

    def __init__(self, repo, a_path, b_path, a_blob, b_blob, a_mode,
                 b_mode, new_file, deleted_file, rename_from,
                 rename_to, diff):
        self.repo = repo

        if not a_blob or re.search(r'^0{40}$', a_blob):
            self.a_blob = None
        else:
            self.a_blob = blob.Blob(repo, id=a_blob, mode=a_mode, path=a_path)
        if not b_blob or re.search(r'^0{40}$', b_blob):
            self.b_blob = None
        else:
            self.b_blob = blob.Blob(repo, id=b_blob, mode=b_mode, path=b_path)

        self.a_mode = a_mode
        self.b_mode = b_mode
        self.new_file = new_file
        self.deleted_file = deleted_file
        self.rename_from = rename_from
        self.rename_to = rename_to
        self.renamed = rename_from != rename_to
        self.diff = diff

    @classmethod
    def list_from_string(cls, repo, text):
        """
        Create a new diff object from the given text
        ``repo``
            is the repository we are operating on - it is required 
        
        ``text``
            result of 'git diff' between two commits or one commit and the index
        
        Returns
            git.Diff[]
        """
        diffs = []

        diff_header = re.compile(r"""
            #^diff[ ]--git
                [ ]a/(?P<a_path>\S+)[ ]b/(?P<b_path>\S+)\n
            (?:^similarity[ ]index[ ](?P<similarity_index>\d+)%\n
               ^rename[ ]from[ ](?P<rename_from>\S+)\n
               ^rename[ ]to[ ](?P<rename_to>\S+)(?:\n|$))?
            (?:^old[ ]mode[ ](?P<old_mode>\d+)\n
               ^new[ ]mode[ ](?P<new_mode>\d+)(?:\n|$))?
            (?:^new[ ]file[ ]mode[ ](?P<new_file_mode>.+)(?:\n|$))?
            (?:^deleted[ ]file[ ]mode[ ](?P<deleted_file_mode>.+)(?:\n|$))?
            (?:^index[ ](?P<a_blob>[0-9A-Fa-f]+)
                \.\.(?P<b_blob>[0-9A-Fa-f]+)[ ]?(?P<b_mode>.+)?(?:\n|$))?
        """, re.VERBOSE | re.MULTILINE).match

        for diff in ('\n' + text).split('\ndiff --git')[1:]:
            header = diff_header(diff)

            a_path, b_path, similarity_index, rename_from, rename_to, \
                old_mode, new_mode, new_file_mode, deleted_file_mode, \
                a_blob, b_blob, b_mode = header.groups()
            new_file, deleted_file = bool(new_file_mode), bool(deleted_file_mode)

            diffs.append(Diff(repo, a_path, b_path, a_blob, b_blob,
                old_mode or deleted_file_mode, new_mode or new_file_mode or b_mode,
                new_file, deleted_file, rename_from, rename_to, diff[header.end():]))

        return diffs

