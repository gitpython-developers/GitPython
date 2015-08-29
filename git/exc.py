# exc.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
""" Module containing all exceptions thrown througout the git package, """

from gitdb.exc import *     # NOQA

from git.compat import defenc


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


class GitCommandError(Exception):
    """ Thrown if execution of the git command fails with non-zero status code. """

    def __init__(self, command, status, stderr=None, stdout=None):
        self.stderr = stderr
        self.stdout = stdout
        self.status = status
        self.command = command

    def __str__(self):
        ret = "'%s' returned with exit code %i" % \
              (' '.join(str(i) for i in self.command), self.status)
        if self.stderr:
            ret += "\nstderr: '%s'" % self.stderr.decode(defenc)
        if self.stdout:
            ret += "\nstdout: '%s'" % self.stdout.decode(defenc)
        return ret


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


class HookExecutionError(Exception):
    """Thrown if a hook exits with a non-zero exit code. It provides access to the exit code and the string returned
    via standard output"""

    def __init__(self, command, status, stdout, stderr):
        self.command = command
        self.status = status
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        return ("'%s' hook returned with exit code %i\nstdout: '%s'\nstderr: '%s'"
                % (self.command, self.status, self.stdout, self.stderr))


class RepositoryDirtyError(Exception):
    """Thrown whenever an operation on a repository fails as it has uncommited changes that would be overwritten"""

    def __init__(self, repo, message):
        self.repo = repo
        self.message = message

    def __str__(self):
        return "Operation cannot be performed on %r: %s" % (self.repo, self.message)
