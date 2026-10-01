# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Git's object database, accessed exclusively through the Git command."""

__all__ = ["GitCmdObjectDB", "GitDB"]

import tempfile
from typing import Iterator, TYPE_CHECKING

from gitdb.base import IStream, OInfo, OStream
from gitdb.db import GitDB

from git.compat import force_text
from git.exc import BadObject, GitCommandError, UnsupportedOperation
from git.types import PathLike
from git.util import bin_to_hex, hex_to_bin

if TYPE_CHECKING:
    from git.cmd import Git


class GitCmdObjectDB:
    """Read and write objects through Git, independently of its storage format.

    The deprecated :class:`GitDB` remains available for applications that require
    its legacy compressed-object and custom-output-stream interfaces.
    """

    def __init__(self, root_path: PathLike, git: "Git") -> None:
        self._root_path = root_path
        self._git = git

    def root_path(self) -> PathLike:
        return self._root_path

    def info(self, binsha: bytes) -> OInfo:
        try:
            hexsha, typename, size = self._git.get_object_header(bin_to_hex(binsha))
        except ValueError as exc:
            raise BadObject(binsha) from exc
        return OInfo(hex_to_bin(hexsha), typename.encode("ascii"), size)

    def stream(self, binsha: bytes) -> OStream:
        try:
            hexsha, typename, size, stream = self._git.stream_object_data(bin_to_hex(binsha))
        except ValueError as exc:
            raise BadObject(binsha) from exc
        return OStream(hex_to_bin(hexsha), typename.encode("ascii"), size, stream)

    def has_object(self, binsha: bytes) -> bool:
        try:
            self.info(binsha)
        except BadObject:
            return False
        return True

    def __contains__(self, binsha: bytes) -> bool:
        return self.has_object(binsha)

    def sha_iter(self) -> Iterator[bytes]:
        proc = self._git._call_process_safe(
            "cat_file", "--batch-all-objects", "--batch-check=%(objectname)", as_process=True
        )
        try:
            for line in proc.stdout:
                yield hex_to_bin(line.strip())
            proc.wait()
        finally:
            proc._terminate()

    def size(self) -> int:
        return sum(1 for _ in self.sha_iter())

    def update_cache(self, force: bool = False) -> bool:
        self._git.clear_cache()
        return True

    def store(self, istream: IStream) -> IStream:
        """Store exactly the declared uncompressed payload using ``hash-object``.

        Validate the input before asking Git to write an object; there is no fallback
        to a Python loose-object writer.
        """
        if istream.binsha is not None:
            raise UnsupportedOperation("Precompressed object storage requires the deprecated GitDB backend")
        typename = force_text(istream.type)
        if typename not in ("blob", "tree", "commit", "tag"):
            raise ValueError(f"Invalid object type: {typename!r}")
        if not isinstance(istream.size, int) or istream.size < 0:
            raise ValueError("Object size must be a nonnegative integer")
        with tempfile.TemporaryFile() as payload:
            remaining = istream.size
            while remaining:
                chunk = istream.read(min(remaining, 512 * 1024))
                if not chunk or len(chunk) > remaining:
                    raise ValueError("Object stream does not match its declared size")
                payload.write(chunk)
                remaining -= len(chunk)
            payload.seek(0)
            hexsha = self._git._call_process_safe("hash_object", "-t", typename, "-w", "--stdin", istream=payload)
        istream.binsha = hex_to_bin(hexsha)
        return istream

    def partial_to_complete_sha_hex(self, partial_hexsha: str) -> bytes:
        """Resolve a revision to its full binary object ID.

        Missing and ambiguous objects raise :class:`git.exc.BadObject`.
        """
        try:
            hexsha, _typename, _size = self._git.get_object_header(partial_hexsha)
            return hex_to_bin(hexsha)
        except (GitCommandError, ValueError) as exc:
            raise BadObject(partial_hexsha) from exc
