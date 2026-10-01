# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Runtime and static checks for public APIs with related input/output types."""

from io import BytesIO, StringIO
import subprocess
import sys
from typing import List, Tuple, TYPE_CHECKING

import pytest

from git import Git
from git.exc import GitCommandError
from git.index.typ import BaseIndexEntry, IndexEntry
from git.util import stream_copy


def test_index_entry_constructor_shapes() -> None:
    class DerivedEntry(IndexEntry):
        pass

    short = (0o100644, b"\0" * 20, 0, "file")
    entries: List[IndexEntry] = [IndexEntry(short), IndexEntry((0o100644, b"a" * 32, 3 << 12, "other"))]
    derived: DerivedEntry = DerivedEntry(short)

    assert all(type(entry) is IndexEntry for entry in entries)
    assert [entry.stage for entry in entries] == [0, 3]
    assert [entry.path for entry in entries] == ["file", "other"]
    with pytest.raises(TypeError, match="raw stat metadata"):
        IndexEntry(short + (b"\0" * 8, b"\0" * 8, 1, 2, 3, 4, 5))
    assert type(derived) is DerivedEntry
    assert IndexEntry.from_base(BaseIndexEntry(short)) == entries[0]


def test_stream_copy_minimal_writer() -> None:
    class Writer:
        def __init__(self) -> None:
            self.data = b""

        def write(self, data: bytes) -> None:
            self.data += data

    writer = Writer()
    assert stream_copy(BytesIO(b"payload"), writer, chunk_size=3) == 7
    assert writer.data == b"payload"
    text = StringIO()
    assert stream_copy(StringIO("payload"), text, chunk_size=3) == 7
    assert text.getvalue() == "payload"


def test_process_wait_with_no_previous_stderr() -> None:
    process = Git().execute(
        [sys.executable, "-c", "import sys; sys.stderr.write('failure'); sys.exit(1)"],
        as_process=True,
        istream=subprocess.DEVNULL,
        shell=False,
    )
    with pytest.raises(GitCommandError, match="failure"):
        process.wait(stderr=None)


def test_execute_output_types() -> None:
    git = Git()
    command = [sys.executable, "-c", "print('payload', end='')"]
    text: str = git.execute(command, with_exceptions=False, shell=False)
    binary: bytes = git.execute(command, stdout_as_string=False, shell=False)
    extended_text: Tuple[int, str, str] = git.execute(command, with_extended_output=True, shell=False)
    extended_binary: Tuple[int, bytes, str] = git.execute(
        command, with_extended_output=True, stdout_as_string=False, shell=False
    )
    assert text == "payload"
    assert binary == b"payload"
    assert extended_text == (0, text, "")
    assert extended_binary == (0, binary, "")


if TYPE_CHECKING:
    from git import Remote, Repo
    from git.repo.base import BlameEntry
    from git.objects import Commit, Submodule

    repo = Repo()
    remote = Remote(repo, "origin")
    removed_names: List[str] = [Remote.remove(repo, "origin"), Remote.rm(repo, "origin"), repo.delete_remote("origin")]
    removed_remotes: List[Remote] = [Remote.remove(repo, remote), Remote.rm(repo, remote), repo.delete_remote(remote)]
    blame = BlameEntry(repo.head.commit, range(1), "file", range(1))
    commit: Commit = blame.commit
    submodule_entry: IndexEntry = IndexEntry.from_blob(Submodule(repo, b"\0" * 20))
    Git().get_object_header(b"HEAD")
    Git().get_object_data(b"HEAD")
    Git().stream_object_data(b"HEAD")
