"""Module with our own git implementation - it uses the git command"""

from git.db.compat import RepoCompatibilityInterface
from git.db.py.complex import PureGitDB

from base import *


__all__ = ['GitCmdDB', 'CmdCompatibilityGitDB', 'CmdPartialGitDB']


class CmdPartialGitDB( 	GitCommandMixin, CmdObjectDBRMixin, CmdTransportMixin, 
						CmdHighLevelRepository ):
	"""Utility repository which only partially implements all required methods.
	It cannot be reliably used alone, but is provided to allow mixing it with other 
	implementations"""
	pass


class CmdGitDB(CmdPartialGitDB, PureGitDB):
	"""A database which fills in its missing implementation using the pure python 
	implementation"""
	pass


class CmdCompatibilityGitDB(CmdGitDB, RepoCompatibilityInterface):
	"""Command git database with the compatabilty interface added for 0.3x code"""
