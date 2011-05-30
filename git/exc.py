# exc.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
""" Module containing all exceptions thrown througout the git package, """

from util import to_hex_sha

class GitPythonError(Exception):
	"""Base exception for all git-python related errors"""

class ODBError(GitPythonError):
	"""All errors thrown by the object database"""


class InvalidDBRoot(ODBError):
	"""Thrown if an object database cannot be initialized at the given path"""


class BadObject(ODBError):
	"""The object with the given SHA does not exist. Instantiate with the 
	failed sha"""
	
	def __str__(self):
		return "BadObject: %s" % to_hex_sha(self.args[0])


class ParseError(ODBError):
	"""Thrown if the parsing of a file failed due to an invalid format"""


class AmbiguousObjectName(ODBError):
	"""Thrown if a possibly shortened name does not uniquely represent a single object
	in the database"""


class BadObjectType(ODBError):
	"""The object had an unsupported type"""


class UnsupportedOperation(ODBError):
	"""Thrown if the given operation cannot be supported by the object database"""


class InvalidGitRepositoryError(InvalidDBRoot):
	""" Thrown if the given repository appears to have an invalid format.  """


class NoSuchPathError(InvalidDBRoot):
	""" Thrown if a path could not be access by the system. """


class GitCommandError(GitPythonError):
	""" Thrown if execution of the git command fails with non-zero status code. """
	def __init__(self, command, status, stderr=None):
		self.stderr = stderr
		self.status = status
		self.command = command
		
	def __str__(self):
		return ("'%s' returned exit status %i: %s" %
					(' '.join(str(i) for i in self.command), self.status, self.stderr))


class CheckoutError(GitPythonError):
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
		
		
class CacheError(GitPythonError):
	"""Base for all errors related to the git index, which is called cache internally"""


class UnmergedEntriesError(CacheError):
	"""Thrown if an operation cannot proceed as there are still unmerged 
	entries in the cache"""
