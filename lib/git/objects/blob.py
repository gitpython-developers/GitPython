# blob.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import mimetypes
import base

class Blob(base.IndexObject):
    """A Blob encapsulates a git blob object"""
    DEFAULT_MIME_TYPE = "text/plain"
    type = "blob"

    __slots__ = tuple()

    
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


    def __repr__(self):
        return '<git.Blob "%s">' % self.sha
