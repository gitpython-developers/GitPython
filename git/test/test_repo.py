# test_repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.lib import *
from git import *
from git.util import join_path_native
from git.exc import BadObject
from gitdb.util import hex_to_bin, bin_to_hex

import os, sys
import tempfile
import shutil
from cStringIO import StringIO


class TestRepo(TestBase):
	
	@raises(InvalidGitRepositoryError)
	def test_new_should_raise_on_invalid_repo_location(self):
		Repo(tempfile.gettempdir())

	@raises(NoSuchPathError)
	def test_new_should_raise_on_non_existant_path(self):
		Repo("repos/foobar")

	def test_repo_creation_from_different_paths(self):
		r_from_gitdir = Repo(self.rorepo.git_dir)
		assert r_from_gitdir.git_dir == self.rorepo.git_dir
		assert r_from_gitdir.git_dir.endswith('.git')
		assert not self.rorepo.git.working_dir.endswith('.git')
		assert r_from_gitdir.git.working_dir == self.rorepo.git.working_dir

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
		
	def test_tree_from_revision(self):
		tree = self.rorepo.tree('0.1.6')
		assert len(tree.hexsha) == 40 
		assert tree.type == "tree"
		assert self.rorepo.tree(tree) == tree
		
		# try from invalid revision that does not exist
		self.failUnlessRaises(BadObject, self.rorepo.tree, 'hello world')
		
	def test_commit_from_revision(self):
		commit = self.rorepo.commit('0.1.4')
		assert commit.type == 'commit'
		assert self.rorepo.commit(commit) == commit

	def test_commits(self):
		mc = 10
		commits = list(self.rorepo.iter_commits('0.1.6', max_count=mc))
		assert len(commits) == mc
		
		c = commits[0]
		assert_equal('9a4b1d4d11eee3c5362a4152216376e634bd14cf', c.hexsha)
		assert_equal(["c76852d0bff115720af3f27acdb084c59361e5f6"], [p.hexsha for p in c.parents])
		assert_equal("ce41fc29549042f1aa09cc03174896cf23f112e3", c.tree.hexsha)
		assert_equal("Michael Trier", c.author.name)
		assert_equal("mtrier@gmail.com", c.author.email)
		assert_equal(1232829715, c.authored_date)
		assert_equal(5*3600, c.author_tz_offset)
		assert_equal("Michael Trier", c.committer.name)
		assert_equal("mtrier@gmail.com", c.committer.email)
		assert_equal(1232829715, c.committed_date)
		assert_equal(5*3600, c.committer_tz_offset)
		assert_equal("Bumped version 0.1.6\n", c.message)

		c = commits[1]
		assert isinstance(c.parents, tuple)

	def test_trees(self):
		mc = 30
		num_trees = 0
		for tree in self.rorepo.iter_trees('0.1.5', max_count=mc):
			num_trees += 1
			assert isinstance(tree, Tree)
		# END for each tree
		assert num_trees == mc


	def _assert_empty_repo(self, repo):
		# test all kinds of things with an empty, freshly initialized repo. 
		# It should throw good errors
		
		# entries should be empty
		assert len(repo.index.entries) == 0
		
		# head is accessible
		assert repo.head
		assert repo.head.ref
		assert not repo.head.is_valid()
		
		# we can change the head to some other ref
		head_ref = Head.from_path(repo, Head.to_full_path('some_head'))
		assert not head_ref.is_valid()
		repo.head.ref = head_ref
		
		# is_dirty can handle all kwargs
		for args in ((1, 0, 0), (0, 1, 0), (0, 0, 1)):
			assert not repo.is_dirty(*args)
		# END for each arg 
		
		# we can add a file to the index ( if we are not bare )
		if not repo.bare:
			pass
		# END test repos with working tree
		

	def test_init(self):
		prev_cwd = os.getcwd()
		os.chdir(tempfile.gettempdir())
		git_dir_rela = "repos/foo/bar.git"
		del_dir_abs = os.path.abspath("repos")
		git_dir_abs = os.path.abspath(git_dir_rela)
		try:
			# with specific path
			for path in (git_dir_rela, git_dir_abs):
				r = Repo.init(path=path, bare=True)
				assert isinstance(r, Repo)
				assert r.bare == True
				assert os.path.isdir(r.git_dir)
				
				self._assert_empty_repo(r)
				
				# test clone
				clone_path = path + "_clone"
				rc = r.clone(clone_path)
				self._assert_empty_repo(rc)
				
				
				try:
					shutil.rmtree(clone_path)
				except OSError:
					# when relative paths are used, the clone may actually be inside
					# of the parent directory
					pass
				# END exception handling
				
				# try again, this time with the absolute version
				rc = Repo.clone_from(r.git_dir, clone_path)
				self._assert_empty_repo(rc)
				
				shutil.rmtree(git_dir_abs)
				try:
					shutil.rmtree(clone_path)
				except OSError:
					# when relative paths are used, the clone may actually be inside
					# of the parent directory
					pass
				# END exception handling
				
			# END for each path
			
			os.makedirs(git_dir_rela)
			os.chdir(git_dir_rela)
			r = Repo.init(bare=False)
			r.bare == False
			
			self._assert_empty_repo(r)
		finally:
			try:
				shutil.rmtree(del_dir_abs)
			except OSError:
				pass
			os.chdir(prev_cwd)
		# END restore previous state
		
	def test_bare_property(self):
		self.rorepo.bare

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
		orig_value = self.rorepo._bare
		self.rorepo._bare = True
		assert_false(self.rorepo.is_dirty())
		self.rorepo._bare = orig_value 

	def test_is_dirty(self):
		self.rorepo._bare = False
		for index in (0,1):
			for working_tree in (0,1):
				for untracked_files in (0,1):
					assert self.rorepo.is_dirty(index, working_tree, untracked_files) in (True, False)
				# END untracked files
			# END working tree
		# END index
		orig_val = self.rorepo._bare
		self.rorepo._bare = True
		assert self.rorepo.is_dirty() == False
		self.rorepo._bare = orig_val

	def test_head(self):
		assert self.rorepo.head.reference.object == self.rorepo.active_branch.object

	def test_index(self):
		index = self.rorepo.index
		assert isinstance(index, IndexFile)
	
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
		
		assert_equal('634396b2f541a9f2d58b00be1a07f0c358b999b3', c.hexsha)
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
		base = self.rorepo.working_tree_dir
		files = (	join_path_native(base, "__test_myfile"), 
					join_path_native(base, "__test_other_file") )
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
				num_test_untracked += join_path_native(base, utfile) in files
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
		
	def test_creation_deletion(self):
		# just a very quick test to assure it generally works. There are 
		# specialized cases in the test_refs module
		head = self.rorepo.create_head("new_head", "HEAD~1")
		self.rorepo.delete_head(head)
		
		tag = self.rorepo.create_tag("new_tag", "HEAD~2")
		self.rorepo.delete_tag(tag)
		self.rorepo.config_writer()
		remote = self.rorepo.create_remote("new_remote", "git@server:repo.git")
		self.rorepo.delete_remote(remote)
		
	def test_comparison_and_hash(self):
		# this is only a preliminary test, more testing done in test_index
		assert self.rorepo == self.rorepo and not (self.rorepo != self.rorepo)
		assert len(set((self.rorepo, self.rorepo))) == 1
		
	def test_git_cmd(self):
		# test CatFileContentStream, just to be very sure we have no fencepost errors
		# last \n is the terminating newline that it expects
		l1 = "0123456789\n"
		l2 = "abcdefghijklmnopqrstxy\n"
		l3 = "z\n" 
		d = "%s%s%s\n" % (l1, l2, l3)
		
		l1p = l1[:5]
		
		# full size
		# size is without terminating newline
		def mkfull():
			return Git.CatFileContentStream(len(d)-1, StringIO(d))
			
		ts = 5
		def mktiny():
			return Git.CatFileContentStream(ts, StringIO(d))
		
		# readlines no limit
		s = mkfull()
		lines = s.readlines()
		assert len(lines) == 3 and lines[-1].endswith('\n')
		assert s._stream.tell() == len(d)	# must have scrubbed to the end
		
		# realines line limit
		s = mkfull()
		lines = s.readlines(5)
		assert len(lines) == 1
		
		# readlines on tiny sections
		s = mktiny()
		lines = s.readlines()
		assert len(lines) == 1 and lines[0] == l1p
		assert s._stream.tell() == ts+1
		
		# readline no limit
		s = mkfull()
		assert s.readline() == l1
		assert s.readline() == l2
		assert s.readline() == l3
		assert s.readline() == ''
		assert s._stream.tell() == len(d)
		
		# readline limit
		s = mkfull()
		assert s.readline(5) == l1p
		assert s.readline() == l1[5:]
		
		# readline on tiny section
		s = mktiny()
		assert s.readline() == l1p
		assert s.readline() == ''
		assert s._stream.tell() == ts+1
		
		# read no limit
		s = mkfull()
		assert s.read() == d[:-1]
		assert s.read() == ''
		assert s._stream.tell() == len(d)
		
		# read limit
		s = mkfull()
		assert s.read(5) == l1p
		assert s.read(6) == l1[5:]
		assert s._stream.tell() == 5 + 6	# its not yet done
		
		# read tiny
		s = mktiny()
		assert s.read(2) == l1[:2]
		assert s._stream.tell() == 2
		assert s.read() == l1[2:ts]
		assert s._stream.tell() == ts+1
		
	def _assert_rev_parse_types(self, name, rev_obj):
		rev_parse = self.rorepo.rev_parse
		
		if rev_obj.type == 'tag':
			rev_obj = rev_obj.object
		
		# tree and blob type
		obj = rev_parse(name + '^{tree}')
		assert obj == rev_obj.tree
		
		obj = rev_parse(name + ':CHANGES')
		assert obj.type == 'blob' and obj.path == 'CHANGES'
		assert rev_obj.tree['CHANGES'] == obj
			
		
	def _assert_rev_parse(self, name):
		"""tries multiple different rev-parse syntaxes with the given name
		:return: parsed object"""
		rev_parse = self.rorepo.rev_parse
		orig_obj = rev_parse(name)
		if orig_obj.type == 'tag':
			obj = orig_obj.object
		else:
			obj = orig_obj
		# END deref tags by default 
		
		# try history
		rev = name + "~"
		obj2 = rev_parse(rev)
		assert obj2 == obj.parents[0]
		self._assert_rev_parse_types(rev, obj2)
		
		# history with number
		ni = 11
		history = [obj.parents[0]]
		for pn in range(ni):
			history.append(history[-1].parents[0])
		# END get given amount of commits
		
		for pn in range(11):
			rev = name + "~%i" % (pn+1)
			obj2 = rev_parse(rev)
			assert obj2 == history[pn]
			self._assert_rev_parse_types(rev, obj2)
		# END history check
		
		# parent ( default )
		rev = name + "^"
		obj2 = rev_parse(rev)
		assert obj2 == obj.parents[0]
		self._assert_rev_parse_types(rev, obj2)
		
		# parent with number
		for pn, parent in enumerate(obj.parents):
			rev = name + "^%i" % (pn+1)
			assert rev_parse(rev) == parent
			self._assert_rev_parse_types(rev, parent)
		# END for each parent
		
		return orig_obj
		
	@with_rw_repo('HEAD', bare=False)
	def test_rw_rev_parse(self, rwrepo):
		# verify it does not confuse branches with hexsha ids
		ahead = rwrepo.create_head('aaaaaaaa')
		assert(rwrepo.rev_parse(str(ahead)) == ahead.commit)
		
	def test_rev_parse(self):
		rev_parse = self.rorepo.rev_parse
		
		# try special case: This one failed at some point, make sure its fixed
		assert rev_parse("33ebe").hexsha == "33ebe7acec14b25c5f84f35a664803fcab2f7781"
		
		# start from reference
		num_resolved = 0
		
		for ref in Reference.iter_items(self.rorepo):
			path_tokens = ref.path.split("/")
			for pt in range(len(path_tokens)):
				path_section = '/'.join(path_tokens[-(pt+1):]) 
				try:
					obj = self._assert_rev_parse(path_section)
					assert obj.type == ref.object.type
					num_resolved += 1
				except BadObject:
					print "failed on %s" % path_section
					# is fine, in case we have something like 112, which belongs to remotes/rname/merge-requests/112
					pass
				# END exception handling
			# END for each token
		# END for each reference
		assert num_resolved
		
		# it works with tags !
		tag = self._assert_rev_parse('0.1.4')
		assert tag.type == 'tag'
		
		# try full sha directly ( including type conversion )
		assert tag.object == rev_parse(tag.object.hexsha)
		self._assert_rev_parse_types(tag.object.hexsha, tag.object)
		
		
		# multiple tree types result in the same tree: HEAD^{tree}^{tree}:CHANGES
		rev = '0.1.4^{tree}^{tree}'
		assert rev_parse(rev) == tag.object.tree
		assert rev_parse(rev+':CHANGES') == tag.object.tree['CHANGES']
		
		
		# try to get parents from first revision - it should fail as no such revision
		# exists
		first_rev = "33ebe7acec14b25c5f84f35a664803fcab2f7781"
		commit = rev_parse(first_rev)
		assert len(commit.parents) == 0
		assert commit.hexsha == first_rev
		self.failUnlessRaises(BadObject, rev_parse, first_rev+"~")
		self.failUnlessRaises(BadObject, rev_parse, first_rev+"^")
		
		# short SHA1
		commit2 = rev_parse(first_rev[:20])
		assert commit2 == commit
		commit2 = rev_parse(first_rev[:5])
		assert commit2 == commit
		
		
		# todo: dereference tag into a blob 0.1.7^{blob} - quite a special one
		# needs a tag which points to a blob
		
		
		# ref^0 returns commit being pointed to, same with ref~0, and ^{}
		tag = rev_parse('0.1.4')
		for token in (('~0', '^0', '^{}')):
			assert tag.object == rev_parse('0.1.4%s' % token)
		# END handle multiple tokens
		
		# try partial parsing
		max_items = 40
		for i, binsha in enumerate(self.rorepo.odb.sha_iter()):
			assert rev_parse(bin_to_hex(binsha)[:8-(i%2)]).binsha == binsha
			if i > max_items:
				# this is rather slow currently, as rev_parse returns an object
				# which requires accessing packs, it has some additional overhead
				break
		# END for each binsha in repo
		
		# missing closing brace commit^{tree
		self.failUnlessRaises(ValueError, rev_parse, '0.1.4^{tree')
		
		# missing starting brace
		self.failUnlessRaises(ValueError, rev_parse, '0.1.4^tree}')
		
		# REVLOG
		#######
		head = self.rorepo.head
		
		# need to specify a ref when using the @ syntax
		self.failUnlessRaises(BadObject, rev_parse, "%s@{0}" % head.commit.hexsha)
		
		# uses HEAD.ref by default
		assert rev_parse('@{0}') == head.commit
		if not head.is_detached:
			refspec = '%s@{0}' % head.ref.name
			assert rev_parse(refspec) == head.ref.commit
			# all additional specs work as well
			assert rev_parse(refspec+"^{tree}") == head.commit.tree
			assert rev_parse(refspec+":CHANGES").type == 'blob'
		#END operate on non-detached head
		
		# the last position
		assert rev_parse('@{1}') != head.commit
		
		# position doesn't exist
		self.failUnlessRaises(IndexError, rev_parse, '@{10000}')
		
		# currently, nothing more is supported
		self.failUnlessRaises(NotImplementedError, rev_parse, "@{1 week ago}")
		
	def test_repo_odbtype(self):
		target_type = GitDB
		if sys.version_info[1] < 5:
			target_type = GitCmdObjectDB
		assert isinstance(self.rorepo.odb, target_type)
			
	def test_submodules(self):
		assert len(self.rorepo.submodules) == 1		# non-recursive
		assert len(list(self.rorepo.iter_submodules())) >= 2
		
		assert isinstance(self.rorepo.submodule("gitdb"), Submodule)
		self.failUnlessRaises(ValueError, self.rorepo.submodule, "doesn't exist")
		
	@with_rw_repo('HEAD', bare=False)
	def test_submodule_update(self, rwrepo):
		# fails in bare mode
		rwrepo._bare = True
		self.failUnlessRaises(InvalidGitRepositoryError, rwrepo.submodule_update)
		rwrepo._bare = False
		
		# test create submodule
		sm = rwrepo.submodules[0]
		sm = rwrepo.create_submodule("my_new_sub", "some_path", join_path_native(self.rorepo.working_tree_dir, sm.path))
		assert isinstance(sm, Submodule)
		
		# note: the rest of this functionality is tested in test_submodule
		
		
