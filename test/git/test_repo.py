# test_repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os, sys
from test.testlib import *
from git import *

class TestRepo(TestBase):
	
	@raises(InvalidGitRepositoryError)
	def test_new_should_raise_on_invalid_repo_location(self):
		if sys.platform == "win32":
			Repo("C:\\WINDOWS\\Temp")
		else:
			Repo("/tmp")

	@raises(NoSuchPathError)
	def test_new_should_raise_on_non_existant_path(self):
		Repo("repos/foobar")

	def test_description(self):
		txt = "Test repository"
		self.rorepo.description = txt
		assert_equal(self.rorepo.description, txt)

	def test_heads_should_return_array_of_head_objects(self):
		for head in self.rorepo.heads:
			assert_equal(Head, head.__class__)

	def test_heads_should_populate_head_data(self):
		for head in self.rorepo.heads:
			assert head.name
			assert isinstance(head.commit,Commit)
		# END for each head 
		
		assert isinstance(self.rorepo.heads.master, Head)
		assert isinstance(self.rorepo.heads['master'], Head)

	@patch_object(Git, '_call_process')
	def test_commits(self, git):
		git.return_value = ListProcessAdapter(fixture('rev_list'))

		commits = list( self.rorepo.iter_commits('master', max_count=10) )
		
		c = commits[0]
		assert_equal('4c8124ffcf4039d292442eeccabdeca5af5c5017', c.id)
		assert_equal(["634396b2f541a9f2d58b00be1a07f0c358b999b3"], [p.id for p in c.parents])
		assert_equal("672eca9b7f9e09c22dcb128c283e8c3c8d7697a4", c.tree.id)
		assert_equal("Tom Preston-Werner", c.author.name)
		assert_equal("tom@mojombo.com", c.author.email)
		assert_equal(1191999972, c.authored_date)
		assert_equal("Tom Preston-Werner", c.committer.name)
		assert_equal("tom@mojombo.com", c.committer.email)
		assert_equal(1191999972, c.committed_date)
		assert_equal("implement Grit#heads", c.message)

		c = commits[1]
		assert_equal(tuple(), c.parents)

		c = commits[2]
		assert_equal(["6e64c55896aabb9a7d8e9f8f296f426d21a78c2c", "7f874954efb9ba35210445be456c74e037ba6af2"], map(lambda p: p.id, c.parents))
		assert_equal("Merge branch 'site'", c.summary)

		assert_true(git.called)

	def test_trees(self):
		mc = 30
		num_trees = 0
		for tree in self.rorepo.iter_trees('0.1.5', max_count=mc):
			num_trees += 1
			assert isinstance(tree, Tree)
		# END for each tree
		assert num_trees == mc
			

	@patch_object(Repo, '__init__')
	@patch_object(Git, '_call_process')
	def test_init(self, git, repo):
		git.return_value = True
		repo.return_value = None

		r = Repo.init("repos/foo/bar.git", bare=True)
		assert isinstance(r, Repo)

		assert_true(git.called)
		assert_true(repo.called)
		
	def test_bare_property(self):
		self.rorepo.bare

	@patch_object(Repo, '__init__')
	@patch_object(Git, '_call_process')
	def test_init_with_options(self, git, repo):
		git.return_value = True
		repo.return_value = None

		r = Repo.init("repos/foo/bar.git", **{'bare' : True,'template': "/baz/sweet"})
		assert isinstance(r, Repo)

		assert_true(git.called)
		assert_true(repo.called)

	@patch_object(Repo, '__init__')
	@patch_object(Git, '_call_process')
	def test_clone(self, git, repo):
		git.return_value = None
		repo.return_value = None

		self.rorepo.clone("repos/foo/bar.git")

		assert_true(git.called)
		path = os.path.join(absolute_project_path(), '.git')
		assert_equal(git.call_args, (('clone', path, 'repos/foo/bar.git'), {}))
		assert_true(repo.called)

	@patch_object(Repo, '__init__')
	@patch_object(Git, '_call_process')
	def test_clone_with_options(self, git, repo):
		git.return_value = None
		repo.return_value = None

		self.rorepo.clone("repos/foo/bar.git", **{'template': '/awesome'})

		assert_true(git.called)
		path = os.path.join(absolute_project_path(), '.git')
		assert_equal(git.call_args, (('clone', path, 'repos/foo/bar.git'),
									  { 'template': '/awesome'}))
		assert_true(repo.called)


	def test_daemon_export(self):
		orig_val = self.rorepo.daemon_export
		self.rorepo.daemon_export = not orig_val
		assert self.rorepo.daemon_export == ( not orig_val )
		self.rorepo.daemon_export = orig_val
		assert self.rorepo.daemon_export == orig_val
  
	def test_alternates(self):
		cur_alternates = self.rorepo.alternates
		# empty alternates
		self.rorepo.alternates = []
		assert self.rorepo.alternates == []
		alts = [ "other/location", "this/location" ]
		self.rorepo.alternates = alts
		assert alts == self.rorepo.alternates
		self.rorepo.alternates = cur_alternates

	def test_repr(self):
		path = os.path.join(os.path.abspath(GIT_REPO), '.git')
		assert_equal('<git.Repo "%s">' % path, repr(self.rorepo))

	def test_is_dirty_with_bare_repository(self):
		self.rorepo._bare = True
		assert_false(self.rorepo.is_dirty)

	def test_is_dirty(self):
		self.rorepo._bare = False
		for index in (0,1):
			for working_tree in (0,1):
				for untracked_files in (0,1):
					assert self.rorepo.is_dirty in (True, False)
				# END untracked files
			# END working tree
		# END index
		self.rorepo._bare = True
		assert self.rorepo.is_dirty == False

	def test_head(self):
		assert self.rorepo.head.reference.object == self.rorepo.active_branch.object
		
	def test_tag(self):
		assert self.rorepo.tag('refs/tags/0.1.5').commit
		
	def test_archive(self):
		tmpfile = os.tmpfile()
		self.rorepo.archive(tmpfile, '0.1.5')
		assert tmpfile.tell()
		
	@patch_object(Git, '_call_process')
	def test_should_display_blame_information(self, git):
		git.return_value = fixture('blame')
		b = self.rorepo.blame( 'master', 'lib/git.py')
		assert_equal(13, len(b))
		assert_equal( 2, len(b[0]) )
		# assert_equal(25, reduce(lambda acc, x: acc + len(x[-1]), b))
		assert_equal(hash(b[0][0]), hash(b[9][0]))
		c = b[0][0]
		assert_true(git.called)
		assert_equal(git.call_args, (('blame', 'master', '--', 'lib/git.py'), {'p': True}))
		
		assert_equal('634396b2f541a9f2d58b00be1a07f0c358b999b3', c.id)
		assert_equal('Tom Preston-Werner', c.author.name)
		assert_equal('tom@mojombo.com', c.author.email)
		assert_equal(1191997100, c.authored_date)
		assert_equal('Tom Preston-Werner', c.committer.name)
		assert_equal('tom@mojombo.com', c.committer.email)
		assert_equal(1191997100, c.committed_date)
		assert_equal('initial grit setup', c.message)
		
		# test the 'lines per commit' entries
		tlist = b[0][1]
		assert_true( tlist )
		assert_true( isinstance( tlist[0], basestring ) )
		assert_true( len( tlist ) < sum( len(t) for t in tlist ) )				 # test for single-char bug
		
	def test_untracked_files(self):
		base = self.rorepo.git.git_dir
		files = (base+"/__test_myfile", base+"/__test_other_file")
		num_recently_untracked = 0
		try:
			for fpath in files:
				fd = open(fpath,"wb")
				fd.close()
			# END for each filename
			untracked_files = self.rorepo.untracked_files
			num_recently_untracked = len(untracked_files)
			
			# assure we have all names - they are relative to the git-dir
			num_test_untracked = 0
			for utfile in untracked_files:
				num_test_untracked += os.path.join(base, utfile) in files
			assert len(files) == num_test_untracked
		finally:
			for fpath in files:
				if os.path.isfile(fpath):
					os.remove(fpath)
		# END handle files 
		
		assert len(self.rorepo.untracked_files) == (num_recently_untracked - len(files))
		
	def test_config_reader(self):
		reader = self.rorepo.config_reader()				# all config files 
		assert reader.read_only
		reader = self.rorepo.config_reader("repository")	# single config file
		assert reader.read_only
		
	def test_config_writer(self):
		for config_level in self.rorepo.config_level:
			try:
				writer = self.rorepo.config_writer(config_level)
				assert not writer.read_only
			except IOError:
				# its okay not to get a writer for some configuration files if we 
				# have no permissions
				pass 
		# END for each config level 
