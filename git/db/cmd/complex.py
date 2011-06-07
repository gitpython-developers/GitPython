"""Module with our own git implementation - it uses the git command"""

from git.db.compat import RepoCompatibilityInterface
from base import *


__all__ = ['CmdPartialGitDB']


class CmdPartialGitDB( 	GitCommandMixin, CmdObjectDBRMixin, CmdTransportMixin, 
						CmdHighLevelRepository ):
	"""Utility repository which only partially implements all required methods.
	It cannot be reliably used alone, but is provided to allow mixing it with other 
	implementations"""
	pass

