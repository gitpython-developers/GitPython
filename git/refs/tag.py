from gitdb.ref.tag import TagReference as GitDB_TagReference

__all__ = ["TagReference", "Tag"]

class TagReference(GitDB_TagReference):
	__slots__ = tuple()
	
	@classmethod
	def create(cls, repo, path, ref='HEAD', message=None, force=False, **kwargs):
		"""Create a new tag reference.
		
		:param path:
			The name of the tag, i.e. 1.0 or releases/1.0. 
			The prefix refs/tags is implied
			
		:param ref:
			A reference to the object you want to tag. It can be a commit, tree or 
			blob.
			
		:param message:
			If not None, the message will be used in your tag object. This will also 
			create an additional tag object that allows to obtain that information, i.e.::
			
				tagref.tag.message
			
		:param force:
			If True, to force creation of a tag even though that tag already exists.
			
		:param kwargs:
			Additional keyword arguments to be passed to git-tag
			
		:return: A new TagReference"""
		args = ( path, ref )
		if message:
			kwargs['m'] =  message
		if force:
			kwargs['f'] = True
		
		repo.git.tag(*args, **kwargs)
		return TagReference(repo, "%s/%s" % (cls._common_path_default, path))
		
	@classmethod
	def delete(cls, repo, *tags):
		"""Delete the given existing tag or tags"""
		repo.git.tag("-d", *tags)
		
# provide an alias
Tag = TagReference
