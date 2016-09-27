# exc.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
""" Module containing all exceptions thrown througout the git package, """

from gitdb.exc import *     # NOQA
from git.compat import UnicodeMixin, safe_decode


class InvalidGitRepositoryError(Exception):
    """ Thrown if the given repository appears to have an invalid format.  """


class WorkTreeRepositoryUnsupported(InvalidGitRepositoryError):
    """ Thrown to indicate we can't handle work tree repositories """


class NoSuchPathError(OSError):
    """ Thrown if a path could not be access by the system. """


class GitCommandNotFound(Exception):
    """Thrown if we cannot find the `git` executable in the PATH or at the path given by
    the GIT_PYTHON_GIT_EXECUTABLE environment variable"""
    pass


class GitCommandError(UnicodeMixin, Exception):
    """ Thrown if execution of the git command fails with non-zero status code. """

    def __init__(self, command, status, stderr=None, stdout=None):
        self.stderr = stderr
        self.stdout = stdout
        self.status = status
        self.command = command

    def __unicode__(self):
        cmdline = u' '.join(safe_decode(i) for i in self.command)
        return (u"'%s' returned with exit code %s\n  stdout: '%s'\n  stderr: '%s'"
                % (cmdline, self.status, safe_decode(self.stdout), safe_decode(self.stderr)))


class CheckoutError(Exception):
    """Thrown if a file could not be checked out from the index as it contained
    changes.

    The .failed_files attribute contains a list of relative paths that failed
    to be checked out as they contained changes that did not exist in the index.

    The .failed_reasons attribute contains a string informing about the actual
    cause of the issue.

    The .valid_files attribute contains a list of relative paths to files that
    were checked out successfully and hence match the version stored in the
    index"""

    def __init__(self, message, failed_files, valid_files, failed_reasons):
        Exception.__init__(self, message)
        self.failed_files = failed_files
        self.failed_reasons = failed_reasons
        self.valid_files = valid_files

    def __str__(self):
        return Exception.__str__(self) + ":%s" % self.failed_files


class CacheError(Exception):

    """Base for all errors related to the git index, which is called cache internally"""


class UnmergedEntriesError(CacheError):
    """Thrown if an operation cannot proceed as there are still unmerged
    entries in the cache"""


class HookExecutionError(UnicodeMixin, Exception):
    """Thrown if a hook exits with a non-zero exit code. It provides access to the exit code and the string returned
    via standard output"""

    def __init__(self, command, status, stdout=None, stderr=None):
        self.command = command
        self.status = status
        self.stdout = stdout
        self.stderr = stderr

    def __unicode__(self):
        cmdline = u' '.join(safe_decode(i) for i in self.command)
        return (u"'%s' hook failed with %r\n  stdout: '%s'\n  stderr: '%s'"
                % (cmdline, self.status, safe_decode(self.stdout), safe_decode(self.stderr)))


class RepositoryDirtyError(Exception):
    """Thrown whenever an operation on a repository fails as it has uncommited changes that would be overwritten"""

    def __init__(self, repo, message):
        self.repo = repo
        self.message = message

    def __str__(self):
        return "Operation cannot be performed on %r: %s" % (self.repo, self.message)
