# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Implement a transport compatible database which sends objects using the git protocol"""

from gitdb.db.interface import ( TransportDB, 
								PushInfo,
								FetchInfo,
								RefSpec )

__all__ = ["PureTransportDB"]

class PurePushInfo(PushInfo):
	"""TODO: Implementation"""
	__slots__ = tuple()
	
		
		
class PureFetchInfo(FetchInfo):
	"""TODO"""
	__slots__ = tuple()
	

class PureTransportDB(TransportDB):
	"""A database which allows to transport objects from and to different locations
	which are specified by urls (location) and refspecs (what to transport, 
	see http://www.kernel.org/pub/software/scm/git/docs/git-fetch.html).
	
	At the beginning of a transport operation, it will be determined which objects
	have to be sent (either by this or by the other side).
	
	Afterwards a pack with the required objects is sent (or received). If there is 
	nothing to send, the pack will be empty.
	
	The communication itself if implemented using a protocol instance which deals
	with the actual formatting of the lines sent.
	
	As refspecs involve symbolic names for references to be handled, we require
	RefParse functionality. How this is done is up to the actual implementation."""
	# The following variables need to be set by the derived class
	#{Configuration
	protocol = None
	#}end configuraiton
	
	#{ Interface
	
	def fetch(self, url, refspecs, progress=None, **kwargs):
		"""Fetch the objects defined by the given refspec from the given url.
		:param url: url identifying the source of the objects. It may also be 
			a symbol from which the respective url can be resolved, like the
			name of the remote. The implementation should allow objects as input
			as well, these are assumed to resovle to a meaningful string though.
		:param refspecs: iterable of reference specifiers or RefSpec instance, 
			identifying the references to be fetch from the remote.
		:param progress: callable which receives progress messages for user consumption
		:param kwargs: may be used for additional parameters that the actual implementation could 
			find useful.
		:return: List of PureFetchInfo compatible instances which provide information about what 
			was previously fetched, in the order of the input refspecs.
		:note: even if the operation fails, one of the returned PureFetchInfo instances
			may still contain errors or failures in only part of the refspecs.
		:raise: if any issue occours during the transport or if the url is not 
			supported by the protocol.
		"""
		raise NotImplementedError()
		
	def push(self, url, refspecs, progress=None, **kwargs):
		"""Transport the objects identified by the given refspec to the remote
		at the given url.
		:param url: Decribes the location which is to receive the objects
			see fetch() for more details
		:param refspecs: iterable of refspecs strings or RefSpec instances
			to identify the objects to push
		:param progress: see fetch() 
		:param kwargs: additional arguments which may be provided by the caller
			as they may be useful to the actual implementation
		:todo: what to return ?
		:raise: if any issue arises during transport or if the url cannot be handled"""
		raise NotImplementedError()
		
	@property
	def remotes(self):
		""":return: An IterableList of Remote objects allowing to access and manipulate remotes
		:note: Remote objects can also be used for the actual push or fetch operation"""
		raise NotImplementedError()
		
	#}end interface

