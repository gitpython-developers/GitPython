# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import contextlib
from dataclasses import dataclass
from io import BytesIO
import logging
import os
import os.path as osp
from pathlib import Path
import re
import shutil
from stat import S_ISLNK, ST_MODE
import subprocess
import sys
import tempfile

from gitdb.base import IStream

import ddt
import pytest

from git import BlobFilter, Diff, Git, IndexFile, Object, Repo, Tree
from git.exc import (
    CheckoutError,
    GitCommandError,
    HookExecutionError,
    InvalidGitRepositoryError,
    UnmergedEntriesError,
)
from git.index.fun import hook_path, run_commit_hook
from git.index.typ import BaseIndexEntry, IndexEntry
from git.index.util import TemporaryFileSwap
from git.objects import Blob
from git.util import Actor, cwd, hex_to_bin, rmtree

from test.lib import (
    TestBase,
    VirtualEnvironment,
    fixture,
    fixture_path,
    with_rw_directory,
    with_rw_repo,
)

HOOKS_SHEBANG = "#!/usr/bin/env sh\n"

_logger = logging.getLogger(__name__)


def _get_windows_ansi_encoding():
    """Get the encoding specified by the Windows system-wide ANSI active code page."""
    # locale.getencoding may work but is only in Python 3.11+. Use the registry instead.
    import winreg

    hklm_path = R"SYSTEM\CurrentControlSet\Control\Nls\CodePage"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hklm_path) as key:
        value, _ = winreg.QueryValueEx(key, "ACP")
    return f"cp{value}"


class WinBashStatus:
    """Namespace of native-Windows bash.exe statuses. Affects what hook tests can pass.

    Call check() to check the status. (CheckError and WinError should not typically be
    used to trigger skip or xfail, because they represent unexpected situations.)
    """

    @dataclass
    class Inapplicable:
        """This system is not native Windows: either not Windows at all, or Cygwin."""

    @dataclass
    class Absent:
        """No command for bash.exe is found on the system."""

    @dataclass
    class Native:
        """Running bash.exe operates outside any WSL distribution (as with Git Bash)."""

    @dataclass
    class Wsl:
        """Running bash.exe calls bash in a WSL distribution."""

    @dataclass
    class WslNoDistro:
        """Running bash.exe tries to run bash on a WSL distribution, but none exists."""

        process: "subprocess.CompletedProcess[bytes]"
        message: str

    @dataclass
    class CheckError:
        """Running bash.exe fails in an unexpected error or gives unexpected output."""

        process: "subprocess.CompletedProcess[bytes]"
        message: str

    @dataclass
    class WinError:
        """bash.exe may exist but can't run. CreateProcessW fails unexpectedly."""

        exception: OSError

    @classmethod
    def check(cls):
        """Check the status of the bash.exe that run_commit_hook will try to use.

        This runs a command with bash.exe and checks the result. On Windows, shell and
        non-shell executable search differ; shutil.which often finds the wrong bash.exe.

        run_commit_hook uses Popen, including to run bash.exe on Windows. It doesn't
        pass shell=True (and shouldn't). On Windows, Popen calls CreateProcessW, which
        checks some locations before using the PATH environment variable. It is expected
        to try System32, even if another directory with the executable precedes it in
        PATH. When WSL is present, even with no distributions, bash.exe usually exists
        in System32; Popen finds it even if a shell would run another one, as on CI.
        (Without WSL, System32 may still have bash.exe; users sometimes put it there.)
        """
        if sys.platform != "win32":
            return cls.Inapplicable()

        try:
            # Output rather than forwarding the test command's exit status so that if a
            # failure occurs before we even get to this point, we will detect it. For
            # information on ways to check for WSL, see https://superuser.com/a/1749811.
            script = 'test -e /proc/sys/fs/binfmt_misc/WSLInterop; echo "$?"'
            command = ["bash.exe", "-c", script]
            process = subprocess.run(command, capture_output=True)
        except FileNotFoundError:
            return cls.Absent()
        except OSError as error:
            return cls.WinError(error)

        text = cls._decode(process.stdout).rstrip()  # stdout includes WSL's own errors.

        if process.returncode == 1 and re.search(r"\bhttps://aka.ms/wslstore\b", text):
            return cls.WslNoDistro(process, text)
        if process.returncode != 0:
            _logger.error("Error running bash.exe to check WSL status: %s", text)
            return cls.CheckError(process, text)
        if text == "0":
            return cls.Wsl()
        if text == "1":
            return cls.Native()
        _logger.error("Strange output checking WSL status: %s", text)
        return cls.CheckError(process, text)

    @staticmethod
    def _decode(stdout):
        """Decode bash.exe output as best we can."""
        # When bash.exe is the WSL wrapper but the output is from WSL itself rather than
        # code running in a distribution, the output is often in UTF-16LE, which Windows
        # uses internally. The UTF-16LE representation of a Windows-style line ending is
        # rarely seen otherwise, so use it to detect this situation.
        if b"\r\0\n\0" in stdout:
            return stdout.decode("utf-16le")

        # At this point, the output is either blank or probably not UTF-16LE. It's often
        # UTF-8 from inside a WSL distro or non-WSL bash shell. Our test command only
        # uses the ASCII subset, so we can safely guess a wrong code page for it. Errors
        # from such an environment can contain any text, but unlike WSL's own messages,
        # they go to stderr, not stdout. So we can try the system ANSI code page first.
        acp = _get_windows_ansi_encoding()
        try:
            return stdout.decode(acp)
        except UnicodeDecodeError:
            pass
        except LookupError as error:
            _logger.warning(str(error))  # Message already says "Unknown encoding:".

        # Assume UTF-8. If invalid, substitute Unicode replacement characters.
        return stdout.decode("utf-8", errors="replace")


_win_bash_status = WinBashStatus.check()


def _make_hook(git_dir, name, content, make_exec=True):
    """A helper to create a hook"""
    hp = hook_path(name, git_dir)
    hpd = osp.dirname(hp)
    if not osp.isdir(hpd):
        os.mkdir(hpd)
    with open(hp, "wt") as fp:
        fp.write(HOOKS_SHEBANG + content)
    if make_exec:
        os.chmod(hp, 0o744)
    return hp


@ddt.ddt
class TestIndex(TestBase):
    def __init__(self, *args):
        super().__init__(*args)
        self._reset_progress()

    def _assert_fprogress(self, entries):
        self.assertEqual(len(entries), len(self._fprogress_map))
        for _path, call_count in self._fprogress_map.items():
            self.assertEqual(call_count, 2)
        # END for each item in progress map
        self._reset_progress()

    def _fprogress(self, path, done, item):
        self._fprogress_map.setdefault(path, 0)
        curval = self._fprogress_map[path]
        if curval == 0:
            assert not done
        if curval == 1:
            assert done
        self._fprogress_map[path] = curval + 1

    def _fprogress_add(self, path, done, item):
        """Called as progress func - we keep track of the proper call order."""
        assert item is not None
        self._fprogress(path, done, item)

    def _reset_progress(self):
        # Maps paths to the count of calls.
        self._fprogress_map = {}

    def _assert_entries(self, entries):
        for entry in entries:
            assert isinstance(entry, BaseIndexEntry)
            assert not osp.isabs(entry.path)
            assert "\\" not in entry.path
        # END for each entry

    def test_index_file_base(self):
        # Read from file.
        index = IndexFile(self.rorepo, fixture_path("index"))
        assert index.entries
        assert index.version > 0

        # Test entry.
        entry = next(iter(index.entries.values()))
        for attr in (
            "path",
            "ctime",
            "mtime",
            "dev",
            "inode",
            "mode",
            "uid",
            "gid",
            "size",
            "binsha",
            "hexsha",
            "stage",
        ):
            getattr(entry, attr)
        # END for each method

        # Test update.
        entries = index.entries
        assert isinstance(index.update(), IndexFile)
        assert entries is not index.entries

        # Test stage.
        index_merge = IndexFile(self.rorepo, fixture_path("index_merge"))
        self.assertEqual(len(index_merge.entries), 106)
        assert len([e for e in index_merge.entries.values() if e.stage != 0])

        # Write the data - it must match the original.
        tmpfile = tempfile.mktemp()
        index_merge.write(tmpfile)
        with open(tmpfile, "rb") as fp:
            self.assertEqual(fp.read(), fixture("index_merge"))
        os.remove(tmpfile)

    def _cmp_tree_index(self, tree, index):
        # Fail unless both objects contain the same paths and blobs.
        if isinstance(tree, str):
            tree = self.rorepo.commit(tree).tree

        blist = []
        for blob in tree.traverse(predicate=lambda e, d: e.type == "blob", branch_first=False):
            assert (blob.path, 0) in index.entries
            blist.append(blob)
        # END for each blob in tree
        if len(blist) != len(index.entries):
            iset = {k[0] for k in index.entries.keys()}
            bset = {b.path for b in blist}
            raise AssertionError(
                "CMP Failed: Missing entries in index: %s, missing in tree: %s" % (bset - iset, iset - bset)
            )
        # END assertion message

    @with_rw_repo("0.1.6")
    def test_index_lock_handling(self, rw_repo):
        def add_bad_blob():
            rw_repo.index.add([Blob(rw_repo, b"f" * 20, "bad-permissions", "foo")])

        try:
            ## First, fail on purpose adding into index.
            add_bad_blob()
        except Exception as ex:
            msg_py3 = "required argument is not an integer"
            msg_py2 = "cannot convert argument to integer"
            assert msg_py2 in str(ex) or msg_py3 in str(ex)

        ## The second time should not fail due to stray lock file.
        try:
            add_bad_blob()
        except Exception as ex:
            assert "index.lock' could not be obtained" not in str(ex)

    @with_rw_repo("0.1.6")
    def test_index_file_from_tree(self, rw_repo):
        common_ancestor_sha = "5117c9c8a4d3af19a9958677e45cda9269de1541"
        cur_sha = "4b43ca7ff72d5f535134241e7c797ddc9c7a3573"
        other_sha = "39f85c4358b7346fee22169da9cad93901ea9eb9"

        # Simple index from tree.
        base_index = IndexFile.from_tree(rw_repo, common_ancestor_sha)
        assert base_index.entries
        self._cmp_tree_index(common_ancestor_sha, base_index)

        # Merge two trees - it's like a fast-forward.
        two_way_index = IndexFile.from_tree(rw_repo, common_ancestor_sha, cur_sha)
        assert two_way_index.entries
        self._cmp_tree_index(cur_sha, two_way_index)

        # Merge three trees - here we have a merge conflict.
        three_way_index = IndexFile.from_tree(rw_repo, common_ancestor_sha, cur_sha, other_sha)
        assert len([e for e in three_way_index.entries.values() if e.stage != 0])

        # ITERATE BLOBS
        merge_required = lambda t: t[0] != 0
        merge_blobs = list(three_way_index.iter_blobs(merge_required))
        assert merge_blobs
        assert merge_blobs[0][0] in (1, 2, 3)
        assert isinstance(merge_blobs[0][1], Blob)

        # Test BlobFilter.
        prefix = "lib/git"
        for _stage, blob in base_index.iter_blobs(BlobFilter([prefix])):
            assert blob.path.startswith(prefix)

        # Writing a tree should fail with an unmerged index.
        self.assertRaises(UnmergedEntriesError, three_way_index.write_tree)

        # Removed unmerged entries.
        unmerged_blob_map = three_way_index.unmerged_blobs()
        assert unmerged_blob_map

        # Pick the first blob at the first stage we find and use it as resolved version.
        three_way_index.resolve_blobs(line[0][1] for line in unmerged_blob_map.values())
        tree = three_way_index.write_tree()
        assert isinstance(tree, Tree)
        num_blobs = 0
        for blob in tree.traverse(predicate=lambda item, d: item.type == "blob"):
            assert (blob.path, 0) in three_way_index.entries
            num_blobs += 1
        # END for each blob
        self.assertEqual(num_blobs, len(three_way_index.entries))

    @with_rw_repo("0.1.6")
    def test_index_merge_tree(self, rw_repo):
        # A bit out of place, but we need a different repo for this:
        self.assertNotEqual(self.rorepo, rw_repo)
        self.assertEqual(len({self.rorepo, self.rorepo, rw_repo, rw_repo}), 2)

        # SINGLE TREE MERGE
        # Current index is at the (virtual) cur_commit.
        next_commit = "4c39f9da792792d4e73fc3a5effde66576ae128c"
        parent_commit = rw_repo.head.commit.parents[0]
        manifest_key = IndexFile.entry_key("MANIFEST.in", 0)
        manifest_entry = rw_repo.index.entries[manifest_key]
        rw_repo.index.merge_tree(next_commit)
        # Only one change should be recorded.
        assert manifest_entry.binsha != rw_repo.index.entries[manifest_key].binsha

        rw_repo.index.reset(rw_repo.head)
        self.assertEqual(rw_repo.index.entries[manifest_key].binsha, manifest_entry.binsha)

        # FAKE MERGE
        #############
        # Add a change with a NULL sha that should conflict with next_commit. We pretend
        # there was a change, but we do not even bother adding a proper sha for it
        # (which makes things faster of course).
        manifest_fake_entry = BaseIndexEntry((manifest_entry[0], b"\0" * 20, 0, manifest_entry[3]))
        # Try write flag.
        self._assert_entries(rw_repo.index.add([manifest_fake_entry], write=False))
        # Add actually resolves the null-hex-sha for us as a feature, but we can edit
        # the index manually.
        assert rw_repo.index.entries[manifest_key].binsha != Object.NULL_BIN_SHA
        # We must operate on the same index for this! It's a bit problematic as it might
        # confuse people.
        index = rw_repo.index
        index.entries[manifest_key] = IndexEntry.from_base(manifest_fake_entry)
        index.write()
        self.assertEqual(rw_repo.index.entries[manifest_key].hexsha, Diff.NULL_HEX_SHA)

        # Write an unchanged index (just for the fun of it).
        rw_repo.index.write()

        # A three way merge would result in a conflict and fails as the command will not
        # overwrite any entries in our index and hence leave them unmerged. This is
        # mainly a protection feature as the current index is not yet in a tree.
        self.assertRaises(GitCommandError, index.merge_tree, next_commit, base=parent_commit)

        # The only way to get the merged entries is to safe the current index away into
        # a tree, which is like a temporary commit for us. This fails as well as the
        # NULL sha does not have a corresponding object.
        # NOTE: missing_ok is not a kwarg anymore, missing_ok is always true.
        # self.assertRaises(GitCommandError, index.write_tree)

        # If missing objects are okay, this would work though (they are always okay
        # now). As we can't read back the tree with NULL_SHA, we rather set it to
        # something else.
        index.entries[manifest_key] = IndexEntry(manifest_entry[:1] + (hex_to_bin("f" * 40),) + manifest_entry[2:])
        tree = index.write_tree()

        # Now make a proper three way merge with unmerged entries.
        unmerged_tree = IndexFile.from_tree(rw_repo, parent_commit, tree, next_commit)
        unmerged_blobs = unmerged_tree.unmerged_blobs()
        self.assertEqual(len(unmerged_blobs), 1)
        self.assertEqual(list(unmerged_blobs.keys())[0], manifest_key[0])

    @with_rw_repo("0.1.6")
    def test_index_file_diffing(self, rw_repo):
        # Default IndexFile instance points to our index.
        index = IndexFile(rw_repo)
        assert index.path is not None
        assert len(index.entries)

        # Write the file back.
        index.write()

        # Could sha it, or check stats.

        # Test diff.
        # Resetting the head will leave the index in a different state, and the diff
        # will yield a few changes.
        cur_head_commit = rw_repo.head.reference.commit
        rw_repo.head.reset("HEAD~6", index=True, working_tree=False)

        # Diff against same index is 0.
        diff = index.diff()
        self.assertEqual(len(diff), 0)

        # Against HEAD as string, must be the same as it matches index.
        diff = index.diff("HEAD")
        self.assertEqual(len(diff), 0)

        # Against previous head, there must be a difference.
        diff = index.diff(cur_head_commit)
        assert len(diff)

        # We reverse the result.
        adiff = index.diff(str(cur_head_commit), R=True)
        odiff = index.diff(cur_head_commit, R=False)  # Now its not reversed anymore.
        assert adiff != odiff
        self.assertEqual(odiff, diff)  # Both unreversed diffs against HEAD.

        # Against working copy - it's still at cur_commit.
        wdiff = index.diff(None)
        assert wdiff != adiff
        assert wdiff != odiff

        # Against something unusual.
        self.assertRaises(ValueError, index.diff, int)

        # Adjust the index to match an old revision.
        cur_branch = rw_repo.active_branch
        cur_commit = cur_branch.commit
        rev_head_parent = "HEAD~1"
        assert index.reset(rev_head_parent) is index

        self.assertEqual(cur_branch, rw_repo.active_branch)
        self.assertEqual(cur_commit, rw_repo.head.commit)

        # There must be differences towards the working tree which is in the 'future'.
        assert index.diff(None)

        # Reset the working copy as well to current head, to pull 'back' as well.
        new_data = b"will be reverted"
        file_path = osp.join(rw_repo.working_tree_dir, "CHANGES")
        with open(file_path, "wb") as fp:
            fp.write(new_data)
        index.reset(rev_head_parent, working_tree=True)
        assert not index.diff(None)
        self.assertEqual(cur_branch, rw_repo.active_branch)
        self.assertEqual(cur_commit, rw_repo.head.commit)
        with open(file_path, "rb") as fp:
            assert fp.read() != new_data

        # Test full checkout.
        test_file = osp.join(rw_repo.working_tree_dir, "CHANGES")
        with open(test_file, "ab") as fd:
            fd.write(b"some data")
        rval = index.checkout(None, force=True, fprogress=self._fprogress)
        assert "CHANGES" in list(rval)
        self._assert_fprogress([None])
        assert osp.isfile(test_file)

        os.remove(test_file)
        rval = index.checkout(None, force=False, fprogress=self._fprogress)
        assert "CHANGES" in list(rval)
        self._assert_fprogress([None])
        assert osp.isfile(test_file)

        # Individual file.
        os.remove(test_file)
        rval = index.checkout(test_file, fprogress=self._fprogress)
        self.assertEqual(list(rval)[0], "CHANGES")
        self._assert_fprogress([test_file])
        assert osp.exists(test_file)

        # Checking out non-existing file throws.
        self.assertRaises(CheckoutError, index.checkout, "doesnt_exist_ever.txt.that")
        self.assertRaises(CheckoutError, index.checkout, paths=["doesnt/exist"])

        # Check out file with modifications.
        append_data = b"hello"
        with open(test_file, "ab") as fp:
            fp.write(append_data)
        try:
            index.checkout(test_file)
        except CheckoutError as e:
            # Detailed exceptions are only possible in older git versions.
            if rw_repo.git.version_info < (2, 29):
                self.assertEqual(len(e.failed_files), 1)
                self.assertEqual(e.failed_files[0], osp.basename(test_file))
                self.assertEqual(len(e.failed_files), len(e.failed_reasons))
                self.assertIsInstance(e.failed_reasons[0], str)
                self.assertEqual(len(e.valid_files), 0)
                with open(test_file, "rb") as fd:
                    s = fd.read()
                self.assertTrue(s.endswith(append_data), s)
        else:
            raise AssertionError("Exception CheckoutError not thrown")

        # If we force it, it should work.
        index.checkout(test_file, force=True)
        assert not open(test_file, "rb").read().endswith(append_data)

        # Check out directory.
        rmtree(osp.join(rw_repo.working_tree_dir, "lib"))
        rval = index.checkout("lib")
        assert len(list(rval)) > 1

    def _count_existing(self, repo, files):
        """Return count of files that actually exist in the repository directory."""
        existing = 0
        basedir = repo.working_tree_dir
        for f in files:
            existing += osp.isfile(osp.join(basedir, f))
        # END for each deleted file
        return existing

    # END num existing helper

    @pytest.mark.xfail(
        sys.platform == "win32" and Git().config("core.symlinks") == "true",
        reason="Assumes symlinks are not created on Windows and opens a symlink to a nonexistent target.",
        raises=FileNotFoundError,
    )
    @with_rw_repo("0.1.6")
    def test_index_mutation(self, rw_repo):
        index = rw_repo.index
        num_entries = len(index.entries)
        cur_head = rw_repo.head

        uname = "Thomas Müller"
        umail = "sd@company.com"
        with rw_repo.config_writer() as writer:
            writer.set_value("user", "name", uname)
            writer.set_value("user", "email", umail)
        self.assertEqual(writer.get_value("user", "name"), uname)

        # Remove all of the files, provide a wild mix of paths, BaseIndexEntries,
        # IndexEntries.
        def mixed_iterator():
            count = 0
            for entry in index.entries.values():
                type_id = count % 5
                if type_id == 0:  # path (str)
                    yield entry.path
                elif type_id == 1:  # path (PathLike)
                    yield Path(entry.path)
                elif type_id == 2:  # blob
                    yield Blob(rw_repo, entry.binsha, entry.mode, entry.path)
                elif type_id == 3:  # BaseIndexEntry
                    yield BaseIndexEntry(entry[:4])
                elif type_id == 4:  # IndexEntry
                    yield entry
                else:
                    raise AssertionError("Invalid Type")
                count += 1
            # END for each entry

        # END mixed iterator
        deleted_files = index.remove(mixed_iterator(), working_tree=False)
        assert deleted_files
        self.assertEqual(self._count_existing(rw_repo, deleted_files), len(deleted_files))
        self.assertEqual(len(index.entries), 0)

        # Reset the index to undo our changes.
        index.reset()
        self.assertEqual(len(index.entries), num_entries)

        # Remove with working copy.
        deleted_files = index.remove(mixed_iterator(), working_tree=True)
        assert deleted_files
        self.assertEqual(self._count_existing(rw_repo, deleted_files), 0)

        # Reset everything.
        index.reset(working_tree=True)
        self.assertEqual(self._count_existing(rw_repo, deleted_files), len(deleted_files))

        # Invalid type.
        self.assertRaises(TypeError, index.remove, [1])

        # Absolute path.
        deleted_files = index.remove([osp.join(rw_repo.working_tree_dir, "lib")], r=True)
        assert len(deleted_files) > 1
        self.assertRaises(ValueError, index.remove, ["/doesnt/exists"])

        # TEST COMMITTING
        # Commit changed index.
        cur_commit = cur_head.commit
        commit_message = "commit default head by Frèderic Çaufl€"

        new_commit = index.commit(commit_message, head=False)
        assert cur_commit != new_commit
        self.assertEqual(new_commit.author.name, uname)
        self.assertEqual(new_commit.author.email, umail)
        self.assertEqual(new_commit.committer.name, uname)
        self.assertEqual(new_commit.committer.email, umail)
        self.assertEqual(new_commit.message, commit_message)
        self.assertEqual(new_commit.parents[0], cur_commit)
        self.assertEqual(len(new_commit.parents), 1)
        self.assertEqual(cur_head.commit, cur_commit)

        # Commit with other actor.
        cur_commit = cur_head.commit

        my_author = Actor("Frèderic Çaufl€", "author@example.com")
        my_committer = Actor("Committing Frèderic Çaufl€", "committer@example.com")
        commit_actor = index.commit(commit_message, author=my_author, committer=my_committer)
        assert cur_commit != commit_actor
        self.assertEqual(commit_actor.author.name, "Frèderic Çaufl€")
        self.assertEqual(commit_actor.author.email, "author@example.com")
        self.assertEqual(commit_actor.committer.name, "Committing Frèderic Çaufl€")
        self.assertEqual(commit_actor.committer.email, "committer@example.com")
        self.assertEqual(commit_actor.message, commit_message)
        self.assertEqual(commit_actor.parents[0], cur_commit)
        self.assertEqual(len(new_commit.parents), 1)
        self.assertEqual(cur_head.commit, commit_actor)
        self.assertEqual(cur_head.log()[-1].actor, my_committer)

        # Commit with author_date and commit_date.
        cur_commit = cur_head.commit
        commit_message = "commit with dates by Avinash Sajjanshetty"

        new_commit = index.commit(
            commit_message,
            author_date="2006-04-07T22:13:13",
            commit_date="2005-04-07T22:13:13",
        )
        assert cur_commit != new_commit
        print(new_commit.authored_date, new_commit.committed_date)
        self.assertEqual(new_commit.message, commit_message)
        self.assertEqual(new_commit.authored_date, 1144447993)
        self.assertEqual(new_commit.committed_date, 1112911993)

        # Same index, no parents.
        commit_message = "index without parents"
        commit_no_parents = index.commit(commit_message, parent_commits=[], head=True)
        self.assertEqual(commit_no_parents.message, commit_message)
        self.assertEqual(len(commit_no_parents.parents), 0)
        self.assertEqual(cur_head.commit, commit_no_parents)

        # same index, multiple parents.
        commit_message = "Index with multiple parents\n    commit with another line"
        commit_multi_parent = index.commit(commit_message, parent_commits=(commit_no_parents, new_commit))
        self.assertEqual(commit_multi_parent.message, commit_message)
        self.assertEqual(len(commit_multi_parent.parents), 2)
        self.assertEqual(commit_multi_parent.parents[0], commit_no_parents)
        self.assertEqual(commit_multi_parent.parents[1], new_commit)
        self.assertEqual(cur_head.commit, commit_multi_parent)

        # Re-add all files in lib.
        # Get the lib folder back on disk, but get an index without it.
        index.reset(new_commit.parents[0], working_tree=True).reset(new_commit, working_tree=False)
        lib_file_path = osp.join("lib", "git", "__init__.py")
        assert (lib_file_path, 0) not in index.entries
        assert osp.isfile(osp.join(rw_repo.working_tree_dir, lib_file_path))

        # Directory.
        entries = index.add(["lib"], fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        assert len(entries) > 1

        # Glob.
        entries = index.reset(new_commit).add([osp.join("lib", "git", "*.py")], fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        self.assertEqual(len(entries), 14)

        # Same file.
        entries = index.reset(new_commit).add(
            [osp.join(rw_repo.working_tree_dir, "lib", "git", "head.py")] * 2,
            fprogress=self._fprogress_add,
        )
        self._assert_entries(entries)
        self.assertEqual(entries[0].mode & 0o644, 0o644)
        # Would fail, test is too primitive to handle this case.
        # self._assert_fprogress(entries)
        self._reset_progress()
        self.assertEqual(len(entries), 2)

        # Missing path.
        self.assertRaises(OSError, index.reset(new_commit).add, ["doesnt/exist/must/raise"])

        # Blob from older revision overrides current index revision.
        old_blob = new_commit.parents[0].tree.blobs[0]
        entries = index.reset(new_commit).add([old_blob], fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        self.assertEqual(index.entries[(old_blob.path, 0)].hexsha, old_blob.hexsha)
        self.assertEqual(len(entries), 1)

        # Mode 0 not allowed.
        null_hex_sha = Diff.NULL_HEX_SHA
        null_bin_sha = b"\0" * 20
        self.assertRaises(
            ValueError,
            index.reset(new_commit).add,
            [BaseIndexEntry((0, null_bin_sha, 0, "doesntmatter"))],
        )

        # Add new file.
        new_file_relapath = "my_new_file"
        self._make_file(new_file_relapath, "hello world", rw_repo)
        entries = index.reset(new_commit).add(
            [BaseIndexEntry((0o10644, null_bin_sha, 0, new_file_relapath))],
            fprogress=self._fprogress_add,
        )
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        self.assertEqual(len(entries), 1)
        self.assertNotEqual(entries[0].hexsha, null_hex_sha)

        # Add symlink.
        if sys.platform != "win32":
            for target in ("/etc/nonexisting", "/etc/passwd", "/etc"):
                basename = "my_real_symlink"

                link_file = osp.join(rw_repo.working_tree_dir, basename)
                os.symlink(target, link_file)
                entries = index.reset(new_commit).add([link_file], fprogress=self._fprogress_add)
                self._assert_entries(entries)
                self._assert_fprogress(entries)
                self.assertEqual(len(entries), 1)
                self.assertTrue(S_ISLNK(entries[0].mode))
                self.assertTrue(S_ISLNK(index.entries[index.entry_key("my_real_symlink", 0)].mode))

                # We expect only the target to be written.
                self.assertEqual(
                    index.repo.odb.stream(entries[0].binsha).read().decode("ascii"),
                    target,
                )

                os.remove(link_file)
            # END for each target
        # END real symlink test

        # Add fake symlink and assure it checks out as a symlink.
        fake_symlink_relapath = "my_fake_symlink"
        link_target = "/etc/that"
        fake_symlink_path = self._make_file(fake_symlink_relapath, link_target, rw_repo)
        fake_entry = BaseIndexEntry((0o120000, null_bin_sha, 0, fake_symlink_relapath))
        entries = index.reset(new_commit).add([fake_entry], fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        assert entries[0].hexsha != null_hex_sha
        self.assertEqual(len(entries), 1)
        self.assertTrue(S_ISLNK(entries[0].mode))

        # Check that this also works with an alternate method.
        full_index_entry = IndexEntry.from_base(BaseIndexEntry((0o120000, entries[0].binsha, 0, entries[0].path)))
        entry_key = index.entry_key(full_index_entry)
        index.reset(new_commit)

        assert entry_key not in index.entries
        index.entries[entry_key] = full_index_entry
        index.write()
        index.update()  # Force reread of entries.
        new_entry = index.entries[entry_key]
        assert S_ISLNK(new_entry.mode)

        # A tree created from this should contain the symlink.
        tree = index.write_tree()
        assert fake_symlink_relapath in tree
        index.write()  # Flush our changes for the checkout.

        # Check out the fake link, should be a link then.
        assert not S_ISLNK(os.stat(fake_symlink_path)[ST_MODE])
        os.remove(fake_symlink_path)
        index.checkout(fake_symlink_path)

        # On Windows, we currently assume we will never get symlinks.
        if sys.platform == "win32":
            # Symlinks should contain the link as text (which is what a
            # symlink actually is).
            with open(fake_symlink_path, "rt") as fd:
                self.assertEqual(fd.read(), link_target)
        else:
            self.assertTrue(S_ISLNK(os.lstat(fake_symlink_path)[ST_MODE]))

        # TEST RENAMING
        def assert_mv_rval(rval):
            for source, dest in rval:
                assert not osp.exists(source) and osp.exists(dest)
            # END for each renamed item

        # END move assertion utility

        self.assertRaises(ValueError, index.move, ["just_one_path"])
        # Try to move a file onto an existing file.
        files = ["AUTHORS", "LICENSE"]
        self.assertRaises(GitCommandError, index.move, files)

        # Again, with force.
        assert_mv_rval(index.move(files, f=True))

        # Move files into a directory - dry run.
        paths = ["LICENSE", "VERSION", "doc"]
        rval = index.move(paths, dry_run=True)
        self.assertEqual(len(rval), 2)
        assert osp.exists(paths[0])

        # Again, no dry run.
        rval = index.move(paths)
        assert_mv_rval(rval)

        # Move dir into dir.
        rval = index.move(["doc", "test"])
        assert_mv_rval(rval)

        # TEST PATH REWRITING
        ######################
        count = [0]

        def rewriter(entry):
            rval = str(count[0])
            count[0] += 1
            return rval

        # END rewriter

        def make_paths():
            """Help out the test by yielding two existing paths and one new path."""
            yield "CHANGES"
            yield "ez_setup.py"
            yield index.entries[index.entry_key("README", 0)]
            yield index.entries[index.entry_key(".gitignore", 0)]

            for fid in range(3):
                fname = "newfile%i" % fid
                with open(fname, "wb") as fd:
                    fd.write(b"abcd")
                yield Blob(rw_repo, Blob.NULL_BIN_SHA, 0o100644, fname)
            # END for each new file

        # END path producer
        paths = list(make_paths())
        self._assert_entries(index.add(paths, path_rewriter=rewriter))

        for filenum in range(len(paths)):
            assert index.entry_key(str(filenum), 0) in index.entries

        # TEST RESET ON PATHS
        ######################
        arela = "aa"
        brela = "bb"
        afile = self._make_file(arela, "adata", rw_repo)
        bfile = self._make_file(brela, "bdata", rw_repo)
        akey = index.entry_key(arela, 0)
        bkey = index.entry_key(brela, 0)
        keys = (akey, bkey)
        absfiles = (afile, bfile)
        files = (arela, brela)

        for fkey in keys:
            assert fkey not in index.entries

        index.add(files, write=True)
        nc = index.commit("2 files committed", head=False)

        for fkey in keys:
            assert fkey in index.entries

        # Just the index.
        index.reset(paths=(arela, afile))
        assert akey not in index.entries
        assert bkey in index.entries

        # Now with working tree - files on disk as well as entries must be recreated.
        rw_repo.head.commit = nc
        for absfile in absfiles:
            os.remove(absfile)

        index.reset(working_tree=True, paths=files)

        for fkey in keys:
            assert fkey in index.entries
        for absfile in absfiles:
            assert osp.isfile(absfile)

    @with_rw_repo("HEAD")
    def test_compare_write_tree(self, rw_repo):
        """Test writing all trees, comparing them for equality."""
        # It's important to have a few submodules in there too.
        max_count = 25
        count = 0
        for commit in rw_repo.head.commit.traverse():
            if count >= max_count:
                break
            count += 1
            index = rw_repo.index.reset(commit)
            orig_tree = commit.tree
            self.assertEqual(index.write_tree(), orig_tree)
        # END for each commit

    @with_rw_repo("HEAD", bare=False)
    def test_index_single_addremove(self, rw_repo):
        fp = osp.join(rw_repo.working_dir, "testfile.txt")
        with open(fp, "w") as fs:
            fs.write("content of testfile")
        self._assert_entries(rw_repo.index.add(fp))
        deleted_files = rw_repo.index.remove(fp)
        assert deleted_files

    def test_index_new(self):
        B = self.rorepo.tree("6d9b1f4f9fa8c9f030e3207e7deacc5d5f8bba4e")
        H = self.rorepo.tree("25dca42bac17d511b7e2ebdd9d1d679e7626db5f")
        M = self.rorepo.tree("e746f96bcc29238b79118123028ca170adc4ff0f")

        for args in ((B,), (B, H), (B, H, M)):
            index = IndexFile.new(self.rorepo, *args)
            assert isinstance(index, IndexFile)
        # END for each arg tuple

    @with_rw_repo("HEAD", bare=True)
    def test_index_bare_add(self, rw_bare_repo):
        # Something is wrong after cloning to a bare repo, reading the property
        # rw_bare_repo.working_tree_dir will return '/tmp' instead of throwing the
        # Exception we are expecting. This is a quick hack to make this test fail when
        # expected.
        assert rw_bare_repo.working_tree_dir is None
        assert rw_bare_repo.bare
        contents = b"This is a BytesIO file"
        filesize = len(contents)
        fileobj = BytesIO(contents)
        filename = "my-imaginary-file"
        istream = rw_bare_repo.odb.store(IStream(Blob.type, filesize, fileobj))
        entry = BaseIndexEntry((0o100644, istream.binsha, 0, filename))
        try:
            rw_bare_repo.index.add([entry])
        except AssertionError:
            self.fail("Adding to the index of a bare repo is not allowed.")

        # Adding using a path should still require a non-bare repository.
        asserted = False
        path = osp.join("git", "test", "test_index.py")
        try:
            rw_bare_repo.index.add([path])
        except InvalidGitRepositoryError:
            asserted = True
        assert asserted, "Adding using a filename is not correctly asserted."

    @with_rw_directory
    def test_add_utf8P_path(self, rw_dir):
        # NOTE: fp is not a Unicode object in Python 2
        # (which is the source of the problem).
        fp = osp.join(rw_dir, "ø.txt")
        with open(fp, "wb") as fs:
            fs.write("content of ø".encode("utf-8"))

        r = Repo.init(rw_dir)
        r.index.add([fp])
        r.index.commit("Added orig and prestable")

    @with_rw_directory
    def test_add_a_file_with_wildcard_chars(self, rw_dir):
        # See issue #407.
        fp = osp.join(rw_dir, "[.exe")
        with open(fp, "wb") as f:
            f.write(b"something")

        r = Repo.init(rw_dir)
        r.index.add([fp])
        r.index.commit("Added [.exe")

    def test__to_relative_path_at_root(self):
        root = osp.abspath(os.sep)

        class Mocked:
            bare = False
            git_dir = root
            working_tree_dir = root

        repo = Mocked()
        path = os.path.join(root, "file")
        index = IndexFile(repo)

        rel = index._to_relative_path(path)
        self.assertEqual(rel, os.path.relpath(path, root))

    @pytest.mark.xfail(
        type(_win_bash_status) is WinBashStatus.Absent,
        reason="Can't run a hook on Windows without bash.exe.",
        raises=HookExecutionError,
    )
    @pytest.mark.xfail(
        type(_win_bash_status) is WinBashStatus.WslNoDistro,
        reason="Currently uses the bash.exe of WSL, even with no WSL distro installed",
        raises=HookExecutionError,
    )
    @with_rw_repo("HEAD", bare=True)
    def test_run_commit_hook(self, rw_repo):
        index = rw_repo.index
        _make_hook(index.repo.git_dir, "fake-hook", "echo 'ran fake hook' >output.txt")
        run_commit_hook("fake-hook", index)
        output = Path(rw_repo.git_dir, "output.txt").read_text(encoding="utf-8")
        self.assertEqual(output, "ran fake hook\n")

    @ddt.data((False,), (True,))
    @with_rw_directory
    def test_hook_uses_shell_not_from_cwd(self, rw_dir, case):
        (chdir_to_repo,) = case

        shell_name = "bash.exe" if sys.platform == "win32" else "sh"
        maybe_chdir = cwd(rw_dir) if chdir_to_repo else contextlib.nullcontext()
        repo = Repo.init(rw_dir)

        # We need an impostor shell that works on Windows and that the test can
        # distinguish from the real bash.exe. But even if the real bash.exe is absent or
        # unusable, we should verify the impostor is not run. So the impostor needs a
        # clear side effect (unlike in TestGit.test_it_executes_git_not_from_cwd). Popen
        # on Windows uses CreateProcessW, which disregards PATHEXT; the impostor may
        # need to be a binary executable to ensure the vulnerability is found if
        # present. No compiler need exist, shipping a binary in the test suite may
        # target the wrong architecture, and generating one in a bespoke way may trigger
        # false positive virus scans. So we use a Bash/Python polyglot for the hook and
        # use the Python interpreter itself as the bash.exe impostor. But an interpreter
        # from a venv may not run when copied outside of it, and a global interpreter
        # won't run when copied to a different location if it was installed from the
        # Microsoft Store. So we make a new venv in rw_dir and use its interpreter.
        venv = VirtualEnvironment(rw_dir, with_pip=False)
        shutil.copy(venv.python, Path(rw_dir, shell_name))
        shutil.copy(fixture_path("polyglot"), hook_path("polyglot", repo.git_dir))
        payload = Path(rw_dir, "payload.txt")

        if type(_win_bash_status) in {WinBashStatus.Absent, WinBashStatus.WslNoDistro}:
            # The real shell can't run, but the impostor should still not be used.
            with self.assertRaises(HookExecutionError):
                with maybe_chdir:
                    run_commit_hook("polyglot", repo.index)
            self.assertFalse(payload.exists())
        else:
            # The real shell should run, and not the impostor.
            with maybe_chdir:
                run_commit_hook("polyglot", repo.index)
            self.assertFalse(payload.exists())
            output = Path(rw_dir, "output.txt").read_text(encoding="utf-8")
            self.assertEqual(output, "Ran intended hook.\n")

    @pytest.mark.xfail(
        type(_win_bash_status) is WinBashStatus.Absent,
        reason="Can't run a hook on Windows without bash.exe.",
        raises=HookExecutionError,
    )
    @pytest.mark.xfail(
        type(_win_bash_status) is WinBashStatus.WslNoDistro,
        reason="Currently uses the bash.exe of WSL, even with no WSL distro installed",
        raises=HookExecutionError,
    )
    @with_rw_repo("HEAD", bare=True)
    def test_pre_commit_hook_success(self, rw_repo):
        index = rw_repo.index
        _make_hook(index.repo.git_dir, "pre-commit", "exit 0")
        index.commit("This should not fail")

    @pytest.mark.xfail(
        type(_win_bash_status) is WinBashStatus.WslNoDistro,
        reason="Currently uses the bash.exe of WSL, even with no WSL distro installed",
        raises=AssertionError,
    )
    @with_rw_repo("HEAD", bare=True)
    def test_pre_commit_hook_fail(self, rw_repo):
        index = rw_repo.index
        hp = _make_hook(index.repo.git_dir, "pre-commit", "echo stdout; echo stderr 1>&2; exit 1")
        try:
            index.commit("This should fail")
        except HookExecutionError as err:
            if type(_win_bash_status) is WinBashStatus.Absent:
                self.assertIsInstance(err.status, OSError)
                self.assertEqual(err.command, [hp])
                self.assertEqual(err.stdout, "")
                self.assertEqual(err.stderr, "")
                assert str(err)
            else:
                self.assertEqual(err.status, 1)
                self.assertEqual(err.command, [hp])
                self.assertEqual(err.stdout, "\n  stdout: 'stdout\n'")
                self.assertEqual(err.stderr, "\n  stderr: 'stderr\n'")
                assert str(err)
        else:
            raise AssertionError("Should have caught a HookExecutionError")

    @pytest.mark.xfail(
        type(_win_bash_status) is WinBashStatus.Absent,
        reason="Can't run a hook on Windows without bash.exe.",
        raises=HookExecutionError,
    )
    @pytest.mark.xfail(
        type(_win_bash_status) is WinBashStatus.Wsl,
        reason="Specifically seems to fail on WSL bash (in spite of #1399)",
        raises=AssertionError,
    )
    @pytest.mark.xfail(
        type(_win_bash_status) is WinBashStatus.WslNoDistro,
        reason="Currently uses the bash.exe of WSL, even with no WSL distro installed",
        raises=HookExecutionError,
    )
    @with_rw_repo("HEAD", bare=True)
    def test_commit_msg_hook_success(self, rw_repo):
        commit_message = "commit default head by Frèderic Çaufl€"
        from_hook_message = "from commit-msg"
        index = rw_repo.index
        _make_hook(
            index.repo.git_dir,
            "commit-msg",
            'printf " {}" >> "$1"'.format(from_hook_message),
        )
        new_commit = index.commit(commit_message)
        self.assertEqual(new_commit.message, "{} {}".format(commit_message, from_hook_message))

    @pytest.mark.xfail(
        type(_win_bash_status) is WinBashStatus.WslNoDistro,
        reason="Currently uses the bash.exe of WSL, even with no WSL distro installed",
        raises=AssertionError,
    )
    @with_rw_repo("HEAD", bare=True)
    def test_commit_msg_hook_fail(self, rw_repo):
        index = rw_repo.index
        hp = _make_hook(index.repo.git_dir, "commit-msg", "echo stdout; echo stderr 1>&2; exit 1")
        try:
            index.commit("This should fail")
        except HookExecutionError as err:
            if type(_win_bash_status) is WinBashStatus.Absent:
                self.assertIsInstance(err.status, OSError)
                self.assertEqual(err.command, [hp])
                self.assertEqual(err.stdout, "")
                self.assertEqual(err.stderr, "")
                assert str(err)
            else:
                self.assertEqual(err.status, 1)
                self.assertEqual(err.command, [hp])
                self.assertEqual(err.stdout, "\n  stdout: 'stdout\n'")
                self.assertEqual(err.stderr, "\n  stderr: 'stderr\n'")
                assert str(err)
        else:
            raise AssertionError("Should have caught a HookExecutionError")

    @with_rw_repo("HEAD")
    def test_index_add_pathlike(self, rw_repo):
        git_dir = Path(rw_repo.git_dir)

        file = git_dir / "file.txt"
        file.touch()

        rw_repo.index.add(file)

    @with_rw_repo("HEAD")
    def test_index_add_non_normalized_path(self, rw_repo):
        git_dir = Path(rw_repo.git_dir)

        file = git_dir / "file.txt"
        file.touch()
        non_normalized_path = file.as_posix()
        if os.name != "nt":
            non_normalized_path = "/" + non_normalized_path[1:].replace("/", "//")

        rw_repo.index.add(non_normalized_path)


class TestIndexUtils:
    @pytest.mark.parametrize("file_path_type", [str, Path])
    def test_temporary_file_swap(self, tmp_path, file_path_type):
        file_path = tmp_path / "foo"
        file_path.write_bytes(b"some data")

        with TemporaryFileSwap(file_path_type(file_path)) as ctx:
            assert Path(ctx.file_path) == file_path
            assert not file_path.exists()

            # Recreate it with new data, so we can observe that they're really separate.
            file_path.write_bytes(b"other data")

            temp_file_path = Path(ctx.tmp_file_path)
            assert temp_file_path.parent == file_path.parent
            assert temp_file_path.name.startswith(file_path.name)
            assert temp_file_path.read_bytes() == b"some data"

        assert not temp_file_path.exists()
        assert file_path.read_bytes() == b"some data"  # Not b"other data".
