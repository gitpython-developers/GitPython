# errors.py
# Copyright (C) 2008-2010 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing all exceptions thrown througout the git package,
"""

class InvalidGitRepositoryError(Exception):
    """
    Thrown if the given repository appears to have an invalid format. 
    """

class NoSuchPathError(Exception):
    """
    Thrown if a path could not be access by the system.
    """

class GitCommandError(Exception):
    """
    Thrown if execution of the git command fails with non-zero status code.
    """
    def __init__(self, command, status, stderr=None):
        self.stderr = stderr
        self.status = status
        self.command = command

    def __str__(self):
        return repr("%s returned exit status %d" %
                    (str(self.command), self.status))

