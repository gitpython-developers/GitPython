# coding: utf-8
# test_diff.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os

from git.test.lib import (
    TestBase,
    StringProcessAdapter,
    fixture,
    assert_equal,
    assert_true,

)

from gitdb.test.lib import with_rw_directory

from git import (
    Repo,
    GitCommandError,
    Diff,
    DiffIndex,
    NULL_TREE,
)


class TestDiff(TestBase):

    def _assert_diff_format(self, diffs):
        # verify that the format of the diff is sane
        for diff in diffs:
            if diff.a_mode:
                assert isinstance(diff.a_mode, int)
            if diff.b_mode:
                assert isinstance(diff.b_mode, int)

            if diff.a_blob:
                assert not diff.a_blob.path.endswith('\n')
            if diff.b_blob:
                assert not diff.b_blob.path.endswith('\n')
        # END for each diff
        return diffs

    @with_rw_directory
    def test_diff_with_staged_file(self, rw_dir):
        # SETUP INDEX WITH MULTIPLE STAGES
        r = Repo.init(rw_dir)
        fp = os.path.join(rw_dir, 'hello.txt')
        with open(fp, 'w') as fs:
            fs.write("hello world")
        r.git.add(fp)
        r.git.commit(message="init")

        with open(fp, 'w') as fs:
            fs.write("Hola Mundo")
        r.git.commit(all=True, message="change on master")

        r.git.checkout('HEAD~1', b='topic')
        with open(fp, 'w') as fs:
            fs.write("Hallo Welt")
        r.git.commit(all=True, message="change on topic branch")

        # there must be a merge-conflict
        self.failUnlessRaises(GitCommandError, r.git.cherry_pick, 'master')

        # Now do the actual testing - this should just work
        assert len(r.index.diff(None)) == 2

        assert len(r.index.diff(None, create_patch=True)) == 0, "This should work, but doesn't right now ... it's OK"

    def test_list_from_string_new_mode(self):
        output = StringProcessAdapter(fixture('diff_new_mode'))
        diffs = Diff._index_from_patch_format(self.rorepo, output.stdout)
        self._assert_diff_format(diffs)

        assert_equal(1, len(diffs))
        assert_equal(8, len(diffs[0].diff.splitlines()))

    def test_diff_with_rename(self):
        output = StringProcessAdapter(fixture('diff_rename'))
        diffs = Diff._index_from_patch_format(self.rorepo, output.stdout)
        self._assert_diff_format(diffs)

        assert_equal(1, len(diffs))

        diff = diffs[0]
        assert_true(diff.renamed_file)
        assert_true(diff.renamed)
        assert_equal(diff.rename_from, u'Jérôme')
        assert_equal(diff.rename_to, u'müller')
        assert isinstance(str(diff), str)

        output = StringProcessAdapter(fixture('diff_rename_raw'))
        diffs = Diff._index_from_raw_format(self.rorepo, output.stdout)
        assert len(diffs) == 1
        diff = diffs[0]
        assert diff.renamed_file
        assert diff.renamed
        assert diff.rename_from == 'this'
        assert diff.rename_to == 'that'
        assert len(list(diffs.iter_change_type('R'))) == 1

    def test_binary_diff(self):
        for method, file_name in ((Diff._index_from_patch_format, 'diff_patch_binary'),
                                  (Diff._index_from_raw_format, 'diff_raw_binary')):
            res = method(None, StringProcessAdapter(fixture(file_name)).stdout)
            assert len(res) == 1
            assert len(list(res.iter_change_type('M'))) == 1
            if res[0].diff:
                assert res[0].diff == b"Binary files a/rps and b/rps differ\n", "in patch mode, we get a diff text"
                assert str(res[0]), "This call should just work"
        # end for each method to test

    def test_diff_index(self):
        output = StringProcessAdapter(fixture('diff_index_patch'))
        res = Diff._index_from_patch_format(None, output.stdout)
        assert len(res) == 6
        for dr in res:
            assert dr.diff.startswith(b'@@')
            assert str(dr), "Diff to string conversion should be possible"
        # end for each diff

        dr = res[3]
        assert dr.diff.endswith(b"+Binary files a/rps and b/rps differ\n")

    def test_diff_index_raw_format(self):
        output = StringProcessAdapter(fixture('diff_index_raw'))
        res = Diff._index_from_raw_format(None, output.stdout)
        assert res[0].deleted_file
        assert res[0].b_path == ''

    def test_diff_initial_commit(self):
        initial_commit = self.rorepo.commit('33ebe7acec14b25c5f84f35a664803fcab2f7781')

        # Without creating a patch...
        diff_index = initial_commit.diff(NULL_TREE)
        assert diff_index[0].b_path == 'CHANGES'
        assert diff_index[0].new_file
        assert diff_index[0].diff == ''

        # ...and with creating a patch
        diff_index = initial_commit.diff(NULL_TREE, create_patch=True)
        assert diff_index[0].a_path is None, repr(diff_index[0].a_path)
        assert diff_index[0].b_path == 'CHANGES', repr(diff_index[0].b_path)
        assert diff_index[0].new_file
        assert diff_index[0].diff == fixture('diff_initial')

    def test_diff_unsafe_paths(self):
        output = StringProcessAdapter(fixture('diff_patch_unsafe_paths'))
        res = Diff._index_from_patch_format(None, output.stdout)

        # The "Additions"
        self.assertEqual(res[0].b_path, u'path/ starting with a space')
        self.assertEqual(res[1].b_path, u'path/"with-quotes"')
        self.assertEqual(res[2].b_path, u"path/'with-single-quotes'")
        self.assertEqual(res[3].b_path, u'path/ending in a space ')
        self.assertEqual(res[4].b_path, u'path/with\ttab')
        self.assertEqual(res[5].b_path, u'path/with\nnewline')
        self.assertEqual(res[6].b_path, u'path/with spaces')
        self.assertEqual(res[7].b_path, u'path/with-question-mark?')
        self.assertEqual(res[8].b_path, u'path/¯\\_(ツ)_|¯')

        # The "Moves"
        # NOTE: The path prefixes a/ and b/ here are legit!  We're actually
        # verifying that it's not "a/a/" that shows up, see the fixture data.
        self.assertEqual(res[9].a_path, u'a/with spaces')       # NOTE: path a/ here legit!
        self.assertEqual(res[9].b_path, u'b/with some spaces')  # NOTE: path b/ here legit!
        self.assertEqual(res[10].a_path, u'a/ending in a space ')
        self.assertEqual(res[10].b_path, u'b/ending with space ')
        self.assertEqual(res[11].a_path, u'a/"with-quotes"')
        self.assertEqual(res[11].b_path, u'b/"with even more quotes"')

    def test_diff_patch_format(self):
        # test all of the 'old' format diffs for completness - it should at least
        # be able to deal with it
        fixtures = ("diff_2", "diff_2f", "diff_f", "diff_i", "diff_mode_only",
                    "diff_new_mode", "diff_numstat", "diff_p", "diff_rename",
                    "diff_tree_numstat_root", "diff_patch_unsafe_paths")

        for fixture_name in fixtures:
            diff_proc = StringProcessAdapter(fixture(fixture_name))
            Diff._index_from_patch_format(self.rorepo, diff_proc.stdout)
        # END for each fixture

    def test_diff_with_spaces(self):
        data = StringProcessAdapter(fixture('diff_file_with_spaces'))
        diff_index = Diff._index_from_patch_format(self.rorepo, data.stdout)
        assert diff_index[0].a_path is None, repr(diff_index[0].a_path)
        assert diff_index[0].b_path == u'file with spaces', repr(diff_index[0].b_path)

    def test_diff_interface(self):
        # test a few variations of the main diff routine
        assertion_map = dict()
        for i, commit in enumerate(self.rorepo.iter_commits('0.1.6', max_count=2)):
            diff_item = commit
            if i % 2 == 0:
                diff_item = commit.tree
            # END use tree every second item

            for other in (None, NULL_TREE, commit.Index, commit.parents[0]):
                for paths in (None, "CHANGES", ("CHANGES", "lib")):
                    for create_patch in range(2):
                        diff_index = diff_item.diff(other=other, paths=paths, create_patch=create_patch)
                        assert isinstance(diff_index, DiffIndex)

                        if diff_index:
                            self._assert_diff_format(diff_index)
                            for ct in DiffIndex.change_type:
                                key = 'ct_%s' % ct
                                assertion_map.setdefault(key, 0)
                                assertion_map[key] = assertion_map[key] + len(list(diff_index.iter_change_type(ct)))
                            # END for each changetype

                            # check entries
                            diff_set = set()
                            diff_set.add(diff_index[0])
                            diff_set.add(diff_index[0])
                            assert len(diff_set) == 1
                            assert diff_index[0] == diff_index[0]
                            assert not (diff_index[0] != diff_index[0])

                            for dr in diff_index:
                                assert str(dr), "Diff to string conversion should be possible"
                        # END diff index checking
                    # END for each patch option
                # END for each path option
            # END for each other side
        # END for each commit

        # assert we could always find at least one instance of the members we
        # can iterate in the diff index - if not this indicates its not working correctly
        # or our test does not span the whole range of possibilities
        for key, value in assertion_map.items():
            assert value, "Did not find diff for %s" % key
        # END for each iteration type

        # test path not existing in the index - should be ignored
        c = self.rorepo.head.commit
        cp = c.parents[0]
        diff_index = c.diff(cp, ["does/not/exist"])
        assert len(diff_index) == 0
