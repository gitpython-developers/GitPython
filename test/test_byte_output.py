"""Git output carries paths and reference names with arbitrary bytes."""

import os
import sys

import pytest

from git import Git, GitCommandError, Repo, RemoteProgress
from git.cmd import handle_process_output
from git.compat import safe_decode, safe_encode
from test.lib.fixtures import writable_fixture


@pytest.mark.parametrize("as_process", [False, True])
def test_text_process_output_preserves_bytes(as_process):
    proc = Git().execute(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'name-\\xff\\n')"],
        universal_newlines=True,
        as_process=as_process,
    )
    if as_process:
        lines = []
        handle_process_output(proc, lines.append, None, decode_streams=False)
        proc.wait()
        assert safe_encode("".join(lines)) == b"name-\xff\n"
    else:
        assert safe_encode(proc) == b"name-\xff"


def test_binary_process_output_handler_preserves_bytes():
    proc = Git().execute(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'name-\\xff\\n')"], as_process=True
    )
    lines = []
    handle_process_output(proc, lines.append, None)
    proc.wait()
    assert safe_encode("".join(lines)) == b"name-\xff\n"


def test_process_error_preserves_previously_read_bytes():
    proc = Git().execute([sys.executable, "-c", "raise SystemExit(1)"], as_process=True)
    with pytest.raises(GitCommandError) as error:
        proc.wait(stderr=safe_decode(b"fatal: name-\xff"))
    assert "name-\udcff" in str(error.value)


def test_progress_preserves_byte_diagnostics():
    progress = RemoteProgress()
    progress._parse_progress_line(b"fatal: name-\xff")
    assert safe_encode(progress.error_lines[0]) == b"fatal: name-\xff"


@pytest.mark.skipif(os.name == "nt", reason="POSIX timeout and byte-argument handling")
def test_timeout_preserves_byte_arguments():
    with pytest.raises(GitCommandError) as error:
        Git().execute(
            [sys.executable, "-c", "import time; time.sleep(5)", safe_decode(b"name-\xff")],
            kill_after_timeout=0.1,
        )
    assert "name-\udcff" in str(error.value)


@pytest.mark.skipif(os.name == "nt", reason="Windows arguments cannot express arbitrary path bytes")
def test_clone_preserves_byte_path_in_failure():
    with writable_fixture("remote-byte-output.sh", "sha1") as temporary:
        root = temporary.path()
        with pytest.raises(GitCommandError) as error:
            Repo.clone_from(root / safe_decode(b"missing-\xff"), root / "clone")
        assert "missing-\udcff" in str(error.value)


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_fetch_and_push_preserve_byte_reference_results(object_format):
    with writable_fixture("remote-byte-output.sh", object_format) as temporary:
        root = temporary.path()
        with Repo(root / "repo") as repo:
            origin = repo.create_remote("origin", str(root / "source"))
            fetched = origin.fetch()
            assert {safe_encode(info.ref.path) for info in fetched} == {
                b"refs/remotes/origin/main",
                b"refs/remotes/origin/branch-\xff",
            }
        with Repo(root / "source") as repo:
            target = repo.create_remote("target", str(root / "target"))
            pushed = target.push("refs/heads/*:refs/heads/*")
            assert not pushed.error
            assert {safe_encode(info.remote_ref_string) for info in pushed} == {
                b"refs/heads/main",
                b"refs/heads/branch-\xff",
            }
