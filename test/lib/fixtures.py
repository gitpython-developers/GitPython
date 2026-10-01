"""Scripted initial states shared by the CLI and Gix test runs."""

from contextlib import contextmanager
import logging
from pathlib import Path
import shutil
from zlib import crc32

from gix import Error, testtools

from git import Repo
from git.util import cwd
from test.cleanup import cleanup_directory


ROOT = Path(__file__).resolve().parents[2]
_logger = logging.getLogger(__name__)


class _WritableFixture:
    """A native fixture whose disposal preserves the suite's cleanup contract."""

    def __init__(self, native):
        self._native = native

    def path(self):
        if self._native is None:
            raise RuntimeError("temporary fixture is closed")
        return self._native.path()

    def close(self, *, keep=False):
        if self._native is None:
            return
        native, self._native = self._native, None
        path = native.path()
        retained = path.with_name(path.name + "-retained")
        try:
            if not keep:
                cleanup_directory(path)
            if path.exists():
                # Release the native owner without deleting retained files.
                try:
                    path.rename(retained)
                except OSError:
                    if keep:
                        try:
                            shutil.copytree(path, retained, symlinks=True)
                        except OSError as error:
                            _logger.warning("Could not copy failed fixture artifacts to %r: %s", str(retained), error)
                        else:
                            _logger.warning("Retained failed fixture artifacts at %r", str(retained))
                    raise
            path.mkdir()
            try:
                native.close()
            finally:
                if retained.exists():
                    retained.rename(path)
        except (OSError, Error) as error:
            _logger.warning("Could not dispose of fixture %r: %s", str(path), error)

    def __enter__(self):
        self.path()
        return self

    def __exit__(self, *args):
        self.close()


@contextmanager
def _script_directory(script):
    with cwd(ROOT):
        try:
            yield
        except Error:
            # Native errors include the whole environment; captured script output is safe.
            raise RuntimeError(f"Fixture script {script!r} failed; see its captured output") from None


def read_only_fixture(script, *args):
    """Return cached script output which callers must not modify."""
    args = list(map(str, args))
    with _script_directory(script):
        # An absolute argument resets the native memoization path; version the full argument list.
        path, _ = testtools.scripted_fixture_read_only_with_args_with_post(
            script, args, crc32(repr((str(script), args)).encode()), lambda state: None
        )
        return path.resolve()


def writable_fixture(script, *args, execute=False):
    """Copy cached output, or execute a declared location-dependent fixture."""
    args = list(map(str, args))
    mode = testtools.Creation.Execute if execute else testtools.Creation.CopyFromReadOnly
    with _script_directory(script):
        temporary, _ = testtools.scripted_fixture_writable_with_args_with_post(
            script, args, mode, crc32(repr((str(script), args)).encode()), lambda state: None
        )
        return _WritableFixture(temporary)


@contextmanager
def fixture_repo(script, *args, write=False, execute=False, subdir="repo"):
    """Open a scripted repository, closing handles before its temporary owner."""
    if write:
        with writable_fixture(script, *args, execute=execute) as temporary:
            with Repo(temporary.path().resolve() / subdir) as repo:
                yield repo
    else:
        if execute:
            raise ValueError("execute requires a writable fixture")
        with Repo(read_only_fixture(script, *args) / subdir) as repo:
            yield repo
