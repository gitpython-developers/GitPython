# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Implement a transport compatible database which sends objects using the git protocol"""

from git.db.interface import ( TransportDB, 
								PushInfo,
								FetchInfo,
								RefSpec )

from git.refs.remote import RemoteReference
from git.remote import Remote


__all__ = ["PureTransportDB"]

class PurePushInfo(PushInfo):
	"""TODO: Implementation"""
	__slots__ = tuple()
	
		
		
class PureFetchInfo(FetchInfo):
	"""TODO"""
	__slots__ = tuple()
	

class PureTransportDB(TransportDB):
	# The following variables need to be set by the derived class
	#{Configuration
	protocol = None
	RemoteCls = Remote
	#}end configuraiton
	
	#{ Interface
	
	def fetch(self, url, refspecs, progress=None, **kwargs):
		raise NotImplementedError()
		
	def push(self, url, refspecs, progress=None, **kwargs):
		raise NotImplementedError()
		
	@property
	def remotes(self):
		return self.RemoteCls.list_items(self)
		
	def remote(self, name='origin'):
		return self.remotes[name]
		
	def create_remote(self, name, url, **kwargs):
		return self.RemoteCls.create(self, name, url, **kwargs)
		
	def delete_remote(self, remote):
		return self.RemoteCls.remove(self, remote)
	
	#}end interface

