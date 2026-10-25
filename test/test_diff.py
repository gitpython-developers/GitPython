# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import os.path as osp

import ddt
import pytest

from git import NULL_TREE, Diff, DiffIndex, Diffable, Repo
from git.compat import safe_encode
from git.diff import decode_path
from git.exc import UnsafeOptionError

from test.lib import StringProcessAdapter, TestBase, fixture
from test.lib.fixtures import fixture_repo, read_only_fixture, writable_fixture


def to_raw(input):
    return input.replace(b"\t", b"\x00")


@pytest.mark.parametrize("change", [b"A", b"D", b"M", b"R100", b"C100"])
def test_raw_diff_preserves_non_utf8_paths(change):
    before = b"legacy-\xf5\t:\n.pas"
    after = b"renamed-\xe3.pas"
    output = b":100644 100644 " + b"1" * 40 + b" " + b"2" * 40 + b" " + change + b"\0" + before + b"\0"
    if change.startswith((b"R", b"C")):
        output += after + b"\0"
    diffs = DiffIndex()
    Diff._handle_diff_line(output, None, diffs)
    assert len(diffs) == 1
    assert diffs[0].a_rawpath == before
    assert diffs[0].b_rawpath == (after if change.startswith((b"R", b"C")) else before)
    if change.startswith(b"R"):
        assert (diffs[0].raw_rename_from, diffs[0].raw_rename_to) == (before, after)


@pytest.mark.parametrize("create_patch", [False, True])
@pytest.mark.parametrize("quote_path", ["false", "true"])
def test_diff_paths_and_renames_preserve_non_utf8_bytes(create_patch, quote_path):
    with fixture_repo("diff-byte-paths.sh", quote_path) as repo:
        before, after = repo.commit("HEAD^"), repo.head.commit
        (diff,) = before.diff(after, create_patch=create_patch)
        assert (diff.a_rawpath, diff.b_rawpath) == (b"legacy-\xff", b"legacy-\xfe")
        assert (diff.raw_rename_from, diff.raw_rename_to) == (diff.a_rawpath, diff.b_rawpath)
        assert (safe_encode(diff.a_path), safe_encode(diff.b_path)) == (diff.a_rawpath, diff.b_rawpath)
        assert (safe_encode(diff.rename_from), safe_encode(diff.rename_to)) == (diff.a_rawpath, diff.b_rawpath)
        assert diff.renamed_file
        if not create_patch:  # Exact-rename patches omit the blob IDs.
            assert before.tree[diff.a_blob.path].binsha == diff.a_blob.binsha
            assert after.tree[diff.b_blob.path].binsha == diff.b_blob.binsha


@ddt.ddt
class TestDiff(TestBase):
    def setUp(self):
        temporary = writable_fixture("empty.sh")
        self.addCleanup(temporary.close)
        self.repo_dir = str(temporary.path())

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

    def test_diff_with_staged_file(self):
        with fixture_repo("diff.sh", "stages", "staged") as repo:
            self.assertEqual(len(repo.index.diff("HEAD", create_patch=True)), 1)
        with fixture_repo("diff.sh", "stages", "committed") as repo:
            self.assertEqual(len(repo.index.diff("HEAD", create_patch=True)), 0)
        with fixture_repo("diff.sh", "stages", "conflict") as repo:
            self.assertEqual(len(repo.index.diff(None)), 2)
            self.assertEqual(len(repo.index.diff(None, create_patch=True)), 0)

    def test_patch_diff_ignores_mnemonic_prefix(self):
        with fixture_repo("diff.sh", "mnemonic", "worktree") as repo:
            self.assertEqual(len(repo.head.commit.diff(None, create_patch=True)), 1)
            self.assertEqual(len(repo.index.diff(None, create_patch=True)), 1)
        with fixture_repo("diff.sh", "mnemonic", "staged") as repo:
            self.assertEqual(len(repo.index.diff(NULL_TREE, create_patch=True)), 1)
            self.assertEqual(repo.git.config("--get", "diff.mnemonicPrefix"), "true")

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
        self.assertTrue(diff.renamed_file)
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
        self.assertIsNotNone(diff.renamed_file)
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

    def test_diff_raw_paths_with_colon_or_line_feed(self):
        fake_meta = ":100644 100644 %s %s M" % ("1" * 40, "2" * 40)
        paths = [":planted", "docs/a\n" + fake_meta, "docs/b", "setup.py"]
        with fixture_repo("diff.sh", "raw-paths") as repo:
            expected = (
                repo.git.diff_tree(
                    "--root",
                    "-r",
                    "--no-commit-id",
                    "--name-status",
                    "-z",
                    "HEAD",
                    "--",
                    stdout_as_string=False,
                )
                .rstrip(b"\0")
                .split(b"\0")
            )
            self.assertEqual(expected[::2], [b"A"] * len(paths))
            self.assertEqual(expected[1::2], [path.encode() for path in sorted(paths)])

            diffs = repo.head.commit.diff(NULL_TREE)
            self.assertEqual([d.b_path for d in diffs], sorted(paths))
            self.assertEqual({d.change_type for d in diffs}, {"A"})

    @ddt.data(
        (b"a/x b/x", b"x"),
        (b"a/x  b/x ", b"x "),
        (b"a/x b/y", None),
        (b"a/x b/xx", None),
        (b"a/x-b/x", None),
        (b"", None),
        (b'"a/x\\t" "b/x\\t"', b"x\t"),
        (b'"a/x\\t" "b/x\\011"', b"x\t"),
        (b'"a/x\\t" "b/y\\t"', None),
        (b'"a/x\\t" "b/x\\t', None),
    )
    def test_same_path_in_header(self, case):
        names, expected = case
        self.assertEqual(Diff._same_path_in_header(names), expected)

    def test_same_path_in_header_copies_linear_bytes(self):
        class SliceCountingBytes(bytes):
            sliced_bytes = 0

            def __getitem__(self, key):
                result = super().__getitem__(key)
                if isinstance(key, slice):
                    self.sliced_bytes += len(result)
                return result

        path = b"x " * 1000
        names = SliceCountingBytes(b"a/" + path + b" b/" + path)
        self.assertEqual(Diff._same_path_in_header(names), path)
        # Count copied bytes rather than asserting a machine-dependent time limit.
        self.assertLessEqual(names.sliced_bytes, 2 * len(names))

    def test_diff_patch_paths_named_only_by_the_header_line(self):
        paths = ["assets b/logo.png", "docs a/empty", "quoted\t a/tab"]
        with fixture_repo("diff.sh", "patch-paths") as repo:
            commit = repo.commit("initial")
            expected = repo.git.diff_tree(
                "--root", "-r", "--no-commit-id", "--name-status", "-z", commit, stdout_as_string=False
            ).split(b"\0")
            self.assertEqual(expected, [part for path in paths for part in (b"A", path.encode())] + [b""])
            diffs = commit.diff(NULL_TREE, create_patch=True)
            self.assertEqual({(d.a_path, d.b_path) for d in diffs}, {(path, path) for path in paths})

            expected = repo.git.diff_tree(
                "-r",
                "-C",
                "--find-copies-harder",
                "--name-status",
                "-z",
                commit,
                repo.head.commit,
                stdout_as_string=False,
            ).split(b"\0")
            self.assertEqual(expected, [b"M", paths[0].encode(), b"C100", paths[0].encode(), b"copy b/logo.png", b""])
            diffs = commit.diff(repo.head.commit, create_patch=True, C=True, find_copies_harder=True)
            self.assertEqual(
                {(d.a_path, d.b_path, d.copied_file) for d in diffs},
                {(paths[0], paths[0], False), (paths[0], "copy b/logo.png", True)},
            )

    def test_diff_patch_mode_only_with_long_space_heavy_path(self):
        path = b"x " * 250000
        with fixture_repo("diff.sh", "patch-long-path") as repo:
            before, after = repo.tree("mode-100644"), repo.tree("mode-100755")
            expected = repo.git.diff_tree("--raw", "-z", before, after, stdout_as_string=False).split(b"\0")
            self.assertTrue(expected[0].startswith(b":100644 100755 "))
            self.assertTrue(expected[0].endswith(b" M"))
            self.assertEqual(expected[1:], [path, b""])
            diffs = before.diff(after, create_patch=True)
            self.assertEqual(len(diffs), 1)
            self.assertEqual((diffs[0].a_rawpath, diffs[0].b_rawpath), (path, path))
            self.assertEqual((diffs[0].a_mode, diffs[0].b_mode), (0o100644, 0o100755))
            self.assertEqual(diffs[0].diff, b"")

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
        self.assertEqual(safe_encode(res[10].b_path), b"path/\x80-invalid-unicode-path.txt")
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

    def test_decode_path_distinguishes_escaped_backslashes_from_octal_bytes(self):
        self.assertEqual(decode_path(b'"foo\\\\899bar"', False), b"foo\\899bar")
        self.assertEqual(decode_path(b'"foo\\\\123bar"', False), b"foo\\123bar")
        self.assertEqual(decode_path(b'"foo\\123bar"', False), b"fooSbar")

    def test_diff_with_spaces(self):
        data = StringProcessAdapter(fixture("diff_file_with_spaces"))
        diff_index = Diff._index_from_patch_format(self.rorepo, data)
        self.assertIsNone(diff_index[0].a_path, repr(diff_index[0].a_path))
        self.assertEqual(diff_index[0].b_path, "file with spaces", repr(diff_index[0].b_path))

    def test_diff_submodule(self):
        fixture = read_only_fixture("diff.sh", "submodule")
        with Repo(fixture / "repo") as repo, Repo(fixture / "repo/sub") as sub:
            first_commit = sub.commit("HEAD~1")
            changed_commit = sub.head.commit
            diff = repo.commit("1").diff(repo.commit("2"))[0]
            for item, commit in ((diff.a_blob, first_commit), (diff.b_blob, changed_commit)):
                self.assertEqual(item.size, commit.size)
                self.assertEqual(item.data_stream.read(), commit.data_stream.read())

    def test_diff_rejects_unsafe_output_options(self):
        commit = self.rorepo.head.commit

        commit.diff(S="needle")

        calls = (
            lambda target: commit.diff(output=target),
            lambda target: commit.diff(other=f"--output={target}"),
            lambda target: commit.diff(O=target),
            lambda target: commit.diff(orderfile=target),
            lambda target: commit.diff(other=f"--orderfile={target}"),
            lambda target: commit.diff(other=f"-pO{target}"),
            lambda target: commit.diff(other=f"-uO{target}"),
            lambda target: commit.diff(other=f"-DO{target}"),
            lambda target: self.rorepo.index.diff(NULL_TREE, output=target),
            lambda target: self.rorepo.index.diff(f"--output={target}"),
            lambda target: self.rorepo.index.diff(NULL_TREE, O=target),
            lambda target: self.rorepo.index.diff(NULL_TREE, orderfile=target),
            lambda target: self.rorepo.index.diff(f"--orderfile={target}"),
            lambda target: self.rorepo.index.diff(f"-pO{target}"),
            lambda target: self.rorepo.index.diff(f"-uO{target}"),
            lambda target: self.rorepo.index.diff(f"-DO{target}"),
        )
        for index, call in enumerate(calls):
            target = osp.join(self.repo_dir, f"diff-output-{index}")
            with self.assertRaises(UnsafeOptionError):
                call(target)
            self.assertFalse(osp.exists(target))

        allowed_target = osp.join(self.repo_dir, "allowed-diff-output")
        commit.diff(output=allowed_target, allow_unsafe_options=True)
        self.assertTrue(osp.isfile(allowed_target))

    def test_diff_rejects_no_index(self):
        calls = (
            lambda: self.rorepo.head.commit.diff(no_index=True),
            lambda: self.rorepo.head.commit.diff(other="--no-index"),
            lambda: self.rorepo.index.diff(None, no_index=True),
            lambda: self.rorepo.index.diff("--no-index"),
        )
        for call in calls:
            with self.assertRaises(UnsafeOptionError):
                call()

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

    def test_rename_override(self):
        with fixture_repo("diff.sh", "rename") as repo:
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

    def test_diff_patch_with_external_engine(self):
        with fixture_repo("diff.sh", "external") as repo:
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

    def test_beginning_space(self):
        with fixture_repo("diff.sh", "space") as repo:
            # Diff the commit with an empty tree
            # and check the paths
            diff_index = repo.head.commit.diff(NULL_TREE)
            d = diff_index[0]
            a_path = d.a_path
            b_path = d.b_path
            self.assertEqual(a_path, " file.txt")
            self.assertEqual(b_path, " file.txt")
