# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import gc
import os.path as osp
import shutil
import sys
import tempfile

import ddt
import pytest

from git import NULL_TREE, Diff, DiffIndex, Diffable, GitCommandError, Repo, Submodule
from git.cmd import Git

from test.lib import StringProcessAdapter, TestBase, fixture, with_rw_directory


def to_raw(input):
    return input.replace(b"\t", b"\x00")


@ddt.ddt
class TestDiff(TestBase):
    def setUp(self):
        self.repo_dir = tempfile.mkdtemp()
        self.submodule_dir = tempfile.mkdtemp()

    def tearDown(self):
        gc.collect()
        shutil.rmtree(self.repo_dir)
        shutil.rmtree(self.submodule_dir)

    def _assert_diff_format(self, diffs):
        # Verify that the format of the diff is sane.
        for diff in diffs:
            if diff.a_mode:
                assert isinstance(diff.a_mode, int)
            if diff.b_mode:
                assert isinstance(diff.b_mode, int)

            if diff.a_blob:
                assert not diff.a_blob.path.endswith("\n")
            if diff.b_blob:
                assert not diff.b_blob.path.endswith("\n")
        # END for each diff
        return diffs

    @with_rw_directory
    def test_diff_with_staged_file(self, rw_dir):
        # SET UP INDEX WITH MULTIPLE STAGES
        r = Repo.init(rw_dir, initial_branch="master")
        fp = osp.join(rw_dir, "hello.txt")
        with open(fp, "w") as fs:
            fs.write("hello world")
        r.git.add(Git.polish_url(fp))
        r.git.commit(message="init")

        with open(fp, "w") as fs:
            fs.write("Hola Mundo")
        r.git.add(Git.polish_url(fp))
        self.assertEqual(
            len(r.index.diff("HEAD", create_patch=True)),
            1,
            "create_patch should generate patch of diff to HEAD",
        )
        r.git.commit(message="change on master")
        self.assertEqual(
            len(r.index.diff("HEAD", create_patch=True)),
            0,
            "create_patch should generate no patch, already on HEAD",
        )

        r.git.checkout("HEAD~1", b="topic")
        with open(fp, "w") as fs:
            fs.write("Hallo Welt")
        r.git.commit(all=True, message="change on topic branch")

        # There must be a merge conflict.
        with self.assertRaises(GitCommandError):
            r.git.cherry_pick("master")

        # Now do the actual testing - this should just work.
        self.assertEqual(len(r.index.diff(None)), 2)

        self.assertEqual(
            len(r.index.diff(None, create_patch=True)),
            0,
            "This should work, but doesn't right now ... it's OK",
        )

    def test_list_from_string_new_mode(self):
        output = StringProcessAdapter(fixture("diff_new_mode"))
        diffs = Diff._index_from_patch_format(self.rorepo, output)
        self._assert_diff_format(diffs)

        self.assertEqual(1, len(diffs))
        self.assertEqual(8, len(diffs[0].diff.splitlines()))

    def test_diff_with_rename(self):
        output = StringProcessAdapter(fixture("diff_rename"))
        diffs = Diff._index_from_patch_format(self.rorepo, output)
        self._assert_diff_format(diffs)

        self.assertEqual(1, len(diffs))

        diff = diffs[0]
        self.assertTrue(diff.renamed_file)
        self.assertTrue(diff.renamed)
        self.assertEqual(diff.rename_from, "Jérôme")
        self.assertEqual(diff.rename_to, "müller")
        self.assertEqual(diff.raw_rename_from, b"J\xc3\xa9r\xc3\xb4me")
        self.assertEqual(diff.raw_rename_to, b"m\xc3\xbcller")
        assert isinstance(str(diff), str)

        output = StringProcessAdapter(to_raw(fixture("diff_rename_raw")))
        diffs = Diff._index_from_raw_format(self.rorepo, output)
        self.assertEqual(len(diffs), 1)
        diff = diffs[0]
        self.assertIsNotNone(diff.renamed_file)
        self.assertIsNotNone(diff.renamed)
        self.assertEqual(diff.rename_from, "this")
        self.assertEqual(diff.rename_to, "that")
        self.assertEqual(diff.change_type, "R")
        self.assertEqual(diff.score, 100)
        self.assertEqual(len(list(diffs.iter_change_type("R"))), 1)

    def test_diff_with_copied_file(self):
        output = StringProcessAdapter(fixture("diff_copied_mode"))
        diffs = Diff._index_from_patch_format(self.rorepo, output)
        self._assert_diff_format(diffs)

        self.assertEqual(1, len(diffs))

        diff = diffs[0]
        self.assertTrue(diff.copied_file)
        self.assertTrue(diff.a_path, "test1.txt")
        self.assertTrue(diff.b_path, "test2.txt")
        assert isinstance(str(diff), str)

        output = StringProcessAdapter(to_raw(fixture("diff_copied_mode_raw")))
        diffs = Diff._index_from_raw_format(self.rorepo, output)
        self.assertEqual(len(diffs), 1)
        diff = diffs[0]
        self.assertEqual(diff.change_type, "C")
        self.assertEqual(diff.score, 100)
        self.assertEqual(diff.a_path, "test1.txt")
        self.assertEqual(diff.b_path, "test2.txt")
        self.assertEqual(len(list(diffs.iter_change_type("C"))), 1)

    def test_diff_with_change_in_type(self):
        output = StringProcessAdapter(fixture("diff_change_in_type"))
        diffs = Diff._index_from_patch_format(self.rorepo, output)
        self._assert_diff_format(diffs)
        self.assertEqual(2, len(diffs))

        diff = diffs[0]
        self.assertIsNotNone(diff.deleted_file)
        self.assertEqual(diff.a_path, "this")
        self.assertEqual(diff.b_path, "this")
        assert isinstance(str(diff), str)

        diff = diffs[1]
        self.assertEqual(diff.a_path, None)
        self.assertEqual(diff.b_path, "this")
        self.assertIsNotNone(diff.new_file)
        assert isinstance(str(diff), str)

        output = StringProcessAdapter(to_raw(fixture("diff_change_in_type_raw")))
        diffs = Diff._index_from_raw_format(self.rorepo, output)
        self.assertEqual(len(diffs), 1)
        diff = diffs[0]
        self.assertEqual(diff.rename_from, None)
        self.assertEqual(diff.rename_to, None)
        self.assertEqual(diff.change_type, "T")
        self.assertEqual(len(list(diffs.iter_change_type("T"))), 1)

    def test_diff_of_modified_files_not_added_to_the_index(self):
        output = StringProcessAdapter(to_raw(fixture("diff_abbrev-40_full-index_M_raw_no-color")))
        diffs = Diff._index_from_raw_format(self.rorepo, output)

        self.assertEqual(len(diffs), 1, "one modification")
        self.assertEqual(len(list(diffs.iter_change_type("M"))), 1, "one modification")
        self.assertEqual(diffs[0].change_type, "M")
        self.assertIsNone(
            diffs[0].b_blob,
        )

    @ddt.data(
        (Diff._index_from_patch_format, "diff_patch_binary"),
        (Diff._index_from_raw_format, "diff_raw_binary"),
    )
    def test_binary_diff(self, case):
        method, file_name = case
        res = method(None, StringProcessAdapter(fixture(file_name)))
        self.assertEqual(len(res), 1)
        self.assertEqual(len(list(res.iter_change_type("M"))), 1)
        if res[0].diff:
            self.assertEqual(
                res[0].diff,
                b"Binary files a/rps and b/rps differ\n",
                "in patch mode, we get a diff text",
            )
            self.assertIsNotNone(str(res[0]), "This call should just work")

    def test_diff_index(self):
        output = StringProcessAdapter(fixture("diff_index_patch"))
        res = Diff._index_from_patch_format(None, output)
        self.assertEqual(len(res), 6)
        for dr in res:
            self.assertTrue(dr.diff.startswith(b"@@"), dr)
            self.assertIsNotNone(str(dr), "Diff to string conversion should be possible")
        # END for each diff

        dr = res[3]
        assert dr.diff.endswith(b"+Binary files a/rps and b/rps differ\n")

    def test_diff_index_raw_format(self):
        output = StringProcessAdapter(fixture("diff_index_raw"))
        res = Diff._index_from_raw_format(None, output)
        self.assertIsNotNone(res[0].deleted_file)
        self.assertIsNone(
            res[0].b_path,
        )

    def test_diff_file_with_colon(self):
        output = fixture("diff_file_with_colon")
        res = []
        Diff._handle_diff_line(output, None, res)
        self.assertEqual(len(res), 3)

    def test_empty_diff(self):
        res = []
        Diff._handle_diff_line(b"", None, res)
        self.assertEqual(res, [])

    def test_diff_initial_commit(self):
        initial_commit = self.rorepo.commit("33ebe7acec14b25c5f84f35a664803fcab2f7781")

        # Without creating a patch...
        diff_index = initial_commit.diff(NULL_TREE)
        self.assertEqual(diff_index[0].b_path, "CHANGES")
        self.assertIsNotNone(diff_index[0].new_file)
        self.assertEqual(diff_index[0].diff, "")

        # ...and with creating a patch.
        diff_index = initial_commit.diff(NULL_TREE, create_patch=True)
        self.assertIsNone(diff_index[0].a_path, repr(diff_index[0].a_path))
        self.assertEqual(diff_index[0].b_path, "CHANGES", repr(diff_index[0].b_path))
        self.assertIsNotNone(diff_index[0].new_file)
        self.assertEqual(diff_index[0].diff, fixture("diff_initial"))

    def test_diff_unsafe_paths(self):
        output = StringProcessAdapter(fixture("diff_patch_unsafe_paths"))
        res = Diff._index_from_patch_format(None, output)

        # The "Additions"
        self.assertEqual(res[0].b_path, "path/ starting with a space")
        self.assertEqual(res[1].b_path, 'path/"with-quotes"')
        self.assertEqual(res[2].b_path, "path/'with-single-quotes'")
        self.assertEqual(res[3].b_path, "path/ending in a space ")
        self.assertEqual(res[4].b_path, "path/with\ttab")
        self.assertEqual(res[5].b_path, "path/with\nnewline")
        self.assertEqual(res[6].b_path, "path/with spaces")
        self.assertEqual(res[7].b_path, "path/with-question-mark?")
        self.assertEqual(res[8].b_path, "path/¯\\_(ツ)_|¯")
        self.assertEqual(res[9].b_path, "path/💩.txt")
        self.assertEqual(res[9].b_rawpath, b"path/\xf0\x9f\x92\xa9.txt")
        self.assertEqual(res[10].b_path, "path/�-invalid-unicode-path.txt")
        self.assertEqual(res[10].b_rawpath, b"path/\x80-invalid-unicode-path.txt")

        # The "Moves"
        # NOTE: The path prefixes "a/" and "b/" here are legit! We're actually verifying
        # that it's not "a/a/" that shows up; see the fixture data.
        self.assertEqual(res[11].a_path, "a/with spaces")  # NOTE: path "a/"" legit!
        self.assertEqual(res[11].b_path, "b/with some spaces")  # NOTE: path "b/"" legit!
        self.assertEqual(res[12].a_path, "a/ending in a space ")
        self.assertEqual(res[12].b_path, "b/ending with space ")
        self.assertEqual(res[13].a_path, 'a/"with-quotes"')
        self.assertEqual(res[13].b_path, 'b/"with even more quotes"')

    def test_diff_patch_format(self):
        # Test all of the 'old' format diffs for completeness - it should at least be
        # able to deal with it.
        fixtures = (
            "diff_2",
            "diff_2f",
            "diff_f",
            "diff_i",
            "diff_mode_only",
            "diff_new_mode",
            "diff_numstat",
            "diff_p",
            "diff_rename",
            "diff_tree_numstat_root",
            "diff_patch_unsafe_paths",
        )

        for fixture_name in fixtures:
            diff_proc = StringProcessAdapter(fixture(fixture_name))
            Diff._index_from_patch_format(self.rorepo, diff_proc)
        # END for each fixture

    def test_diff_with_spaces(self):
        data = StringProcessAdapter(fixture("diff_file_with_spaces"))
        diff_index = Diff._index_from_patch_format(self.rorepo, data)
        self.assertIsNone(diff_index[0].a_path, repr(diff_index[0].a_path))
        self.assertEqual(diff_index[0].b_path, "file with spaces", repr(diff_index[0].b_path))

    @pytest.mark.xfail(
        sys.platform == "win32",
        reason='"Access is denied" when tearDown calls shutil.rmtree',
        raises=PermissionError,
    )
    def test_diff_submodule(self):
        """Test that diff is able to correctly diff commits that cover submodule changes"""
        # Init a temp git repo that will be referenced as a submodule.
        sub = Repo.init(self.submodule_dir)
        with open(self.submodule_dir + "/subfile", "w") as sub_subfile:
            sub_subfile.write("")
        sub.index.add(["subfile"])
        sub.index.commit("first commit")

        # Init a temp git repo that will incorporate the submodule.
        repo = Repo.init(self.repo_dir)
        with open(self.repo_dir + "/test", "w") as foo_test:
            foo_test.write("")
        repo.index.add(["test"])
        Submodule.add(repo, "subtest", "sub", url="file://" + self.submodule_dir)
        repo.index.commit("first commit")
        repo.create_tag("1")

        # Add a commit to the submodule.
        submodule = repo.submodule("subtest")
        with open(self.repo_dir + "/sub/subfile", "w") as foo_sub_subfile:
            foo_sub_subfile.write("blub")
        submodule.module().index.add(["subfile"])
        submodule.module().index.commit("changed subfile")
        submodule.binsha = submodule.module().head.commit.binsha

        # Commit submodule updates in parent repo.
        repo.index.add([submodule])
        repo.index.commit("submodule changed")
        repo.create_tag("2")

        diff = repo.commit("1").diff(repo.commit("2"))[0]
        # If diff is unable to find the commit hashes (looks in wrong repo) the
        # *_blob.size property will be a string containing exception text, an int
        # indicates success.
        self.assertIsInstance(diff.a_blob.size, int)
        self.assertIsInstance(diff.b_blob.size, int)

    def test_diff_interface(self):
        """Test a few variations of the main diff routine."""
        assertion_map = {}
        for i, commit in enumerate(self.rorepo.iter_commits("0.1.6", max_count=2)):
            diff_item = commit
            if i % 2 == 0:
                diff_item = commit.tree
            # END use tree every second item

            for other in (None, NULL_TREE, commit.INDEX, commit.parents[0]):
                for paths in (None, "CHANGES", ("CHANGES", "lib")):
                    for create_patch in range(2):
                        diff_index = diff_item.diff(other=other, paths=paths, create_patch=create_patch)
                        assert isinstance(diff_index, DiffIndex)

                        if diff_index:
                            self._assert_diff_format(diff_index)
                            for ct in DiffIndex.change_type:
                                key = "ct_%s" % ct
                                assertion_map.setdefault(key, 0)
                                assertion_map[key] = assertion_map[key] + len(list(diff_index.iter_change_type(ct)))
                            # END for each changetype

                            # Check entries.
                            diff_set = set()
                            diff_set.add(diff_index[0])
                            diff_set.add(diff_index[0])
                            self.assertEqual(len(diff_set), 1)
                            self.assertEqual(diff_index[0], diff_index[0])
                            self.assertFalse(diff_index[0] != diff_index[0])

                            for dr in diff_index:
                                self.assertIsNotNone(
                                    str(dr),
                                    "Diff to string conversion should be possible",
                                )
                        # END diff index checking
                    # END for each patch option
                # END for each path option
            # END for each other side
        # END for each commit

        # Assert that we could always find at least one instance of the members we can
        # iterate in the diff index - if not this indicates its not working correctly or
        # our test does not span the whole range of possibilities.
        for key, value in assertion_map.items():
            self.assertIsNotNone(value, "Did not find diff for %s" % key)
        # END for each iteration type

        # Test path not existing in the index - should be ignored.
        c = self.rorepo.head.commit
        cp = c.parents[0]
        diff_index = c.diff(cp, ["does/not/exist"])
        self.assertEqual(len(diff_index), 0)

    def test_diff_interface_stability(self):
        """Test that the Diffable.Index redefinition should not break compatibility."""
        self.assertIs(
            Diffable.Index,
            Diffable.INDEX,
            "The old and new class attribute names must be aliases.",
        )
        self.assertIs(
            type(Diffable.INDEX).__eq__,
            object.__eq__,
            "Equality comparison must be reference-based.",
        )

    @with_rw_directory
    def test_rename_override(self, rw_dir):
        """Test disabling of diff rename detection."""
        # Create and commit file_a.txt.
        repo = Repo.init(rw_dir)
        file_a = osp.join(rw_dir, "file_a.txt")
        with open(file_a, "w", encoding="utf-8") as outfile:
            outfile.write("hello world\n")
        repo.git.add(Git.polish_url(file_a))
        repo.git.commit(message="Added file_a.txt")

        # Remove file_a.txt.
        repo.git.rm(Git.polish_url(file_a))

        # Create and commit file_b.txt with similarity index of 52.
        file_b = osp.join(rw_dir, "file_b.txt")
        with open(file_b, "w", encoding="utf-8") as outfile:
            outfile.write("hello world\nhello world")
        repo.git.add(Git.polish_url(file_b))
        repo.git.commit(message="Removed file_a.txt. Added file_b.txt")

        commit_a = repo.commit("HEAD")
        commit_b = repo.commit("HEAD~1")

        # Check default diff command with renamed files enabled.
        diffs = commit_b.diff(commit_a)
        self.assertEqual(1, len(diffs))
        diff = diffs[0]
        self.assertEqual(True, diff.renamed_file)
        self.assertEqual("file_a.txt", diff.rename_from)
        self.assertEqual("file_b.txt", diff.rename_to)

        # Check diff with rename files disabled.
        diffs = commit_b.diff(commit_a, no_renames=True)
        self.assertEqual(2, len(diffs))

        # Check fileA.txt deleted.
        diff = diffs[0]
        self.assertEqual(True, diff.deleted_file)
        self.assertEqual("file_a.txt", diff.a_path)

        # Check fileB.txt added.
        diff = diffs[1]
        self.assertEqual(True, diff.new_file)
        self.assertEqual("file_b.txt", diff.a_path)

        # Check diff with high similarity index.
        diffs = commit_b.diff(commit_a, split_single_char_options=False, M="75%")
        self.assertEqual(2, len(diffs))

        # Check fileA.txt deleted.
        diff = diffs[0]
        self.assertEqual(True, diff.deleted_file)
        self.assertEqual("file_a.txt", diff.a_path)

        # Check fileB.txt added.
        diff = diffs[1]
        self.assertEqual(True, diff.new_file)
        self.assertEqual("file_b.txt", diff.a_path)

        # Check diff with low similarity index.
        diffs = commit_b.diff(commit_a, split_single_char_options=False, M="40%")
        self.assertEqual(1, len(diffs))
        diff = diffs[0]
        self.assertEqual(True, diff.renamed_file)
        self.assertEqual("file_a.txt", diff.rename_from)
        self.assertEqual("file_b.txt", diff.rename_to)

    @with_rw_directory
    def test_diff_patch_with_external_engine(self, rw_dir):
        repo = Repo.init(rw_dir)
        gitignore = osp.join(rw_dir, ".gitignore")

        # First commit
        with open(gitignore, "w") as f:
            f.write("first_line\n")
        repo.git.add(".gitignore")
        repo.index.commit("first commit")

        # Adding second line and committing
        with open(gitignore, "a") as f:
            f.write("second_line\n")
        repo.git.add(".gitignore")
        repo.index.commit("second commit")

        # Adding third line and staging
        with open(gitignore, "a") as f:
            f.write("third_line\n")
        repo.git.add(".gitignore")

        # Adding fourth line
        with open(gitignore, "a") as f:
            f.write("fourth_line\n")

        # Set the external diff engine
        with repo.config_writer(config_level="repository") as writer:
            writer.set_value("diff", "external", "bogus_diff_engine")

        head_against_head = repo.head.commit.diff("HEAD^", create_patch=True)
        self.assertEqual(len(head_against_head), 1)
        head_against_index = repo.head.commit.diff(create_patch=True)
        self.assertEqual(len(head_against_index), 1)
        head_against_working_tree = repo.head.commit.diff(None, create_patch=True)
        self.assertEqual(len(head_against_working_tree), 1)

        index_against_head = repo.index.diff("HEAD", create_patch=True)
        self.assertEqual(len(index_against_head), 1)
        index_against_working_tree = repo.index.diff(None, create_patch=True)
        self.assertEqual(len(index_against_working_tree), 1)

    @with_rw_directory
    def test_beginning_space(self, rw_dir):
        # Create a file beginning by a whitespace
        repo = Repo.init(rw_dir)
        file = osp.join(rw_dir, " file.txt")
        with open(file, "w") as f:
            f.write("hello world")
        repo.git.add(Git.polish_url(file))
        repo.index.commit("first commit")

        # Diff the commit with an empty tree
        # and check the paths
        diff_index = repo.head.commit.diff(NULL_TREE)
        d = diff_index[0]
        a_path = d.a_path
        b_path = d.b_path
        self.assertEqual(a_path, " file.txt")
        self.assertEqual(b_path, " file.txt")
