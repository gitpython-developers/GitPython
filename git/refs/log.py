# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Repository reflogs exposed through Git's commit reflog view."""

__all__ = ["RefLog", "RefLogEntry"]

import re
from typing import List, NamedTuple, TYPE_CHECKING, Tuple

from git.exc import GitCommandError
from git.objects.util import parse_actor_and_date, utctz_to_altz
from git.util import Actor

if TYPE_CHECKING:
    from git.refs import SymbolicReference


class RefLogEntry(NamedTuple):
    """A commit reflog entry returned by Git.

    Git exposes the new object ID, reflog identity, date, and message. It does
    not expose raw old object IDs, so these entries do not have ``oldhexsha``.
    """

    newhexsha: str
    actor: Actor
    time: Tuple[int, int]
    message: str


class RefLog(List[RefLogEntry]):
    """A snapshot of a reference's commit reflog, oldest entry first.

    Git omits entries whose new object is unavailable or is not a commit.
    The snapshot is associated with a reference, not an on-disk reflog file;
    file serialization and rewriting arbitrary reflog history are unsupported.
    """

    def __init__(self, ref: "SymbolicReference") -> None:
        ref._get_validated_ref_path(ref.repo, ref.path)
        self.ref = ref
        try:
            ref.repo.git._call_process_safe("reflog", "exists", "--", ref.path)
        except GitCommandError as exc:
            if exc.status == 1:
                super().__init__()
                return
            raise
        output = ref.repo.git._call_process_safe(
            "reflog",
            "show",
            "--format=%H%x00%gn%x00%ge%x00%gD%x00%gs",
            "--date=raw",
            "-z",
            "--no-abbrev",
            "--no-decorate",
            "--no-notes",
            "--no-color",
            ref.path,
            "--",
        )
        fields = output.split("\0")
        if fields[-1] == "":
            fields.pop()
        if len(fields) % 5:
            raise ValueError("Invalid reflog output from Git")
        entries = []
        for i in range(0, len(fields), 5):
            oid, name, email, selector, message = fields[i : i + 5]
            timestamp, offset = selector.rsplit("@{", 1)[1][:-1].split()
            entries.append(RefLogEntry(oid, Actor(name, email), (int(timestamp), utctz_to_altz(offset)), message))
        super().__init__(reversed(entries))

    @classmethod
    def append_entry(
        cls,
        ref: "SymbolicReference",
        oldbinsha: bytes,
        newbinsha: bytes,
        message: str,
    ) -> RefLogEntry:
        """Append a repository reflog entry without moving the reference.

        The committer identity/date follow Git's environment and configuration.
        Null object IDs are accepted; non-null IDs must identify existing objects.
        """
        ref._get_validated_ref_path(ref.repo, ref.path)
        if not isinstance(oldbinsha, bytes) or not isinstance(newbinsha, bytes):
            raise ValueError("Object IDs must be binary")
        if len(oldbinsha) != ref.repo._oid_size or len(newbinsha) != ref.repo._oid_size:
            raise ValueError("Object IDs must match the repository's object format")
        if "\0" in message:
            raise ValueError("Reflog messages must not contain NUL")
        # Pin Git's own identity/date so the return value describes this write,
        # even when another process appends immediately afterwards.
        identity = ref.repo.git._call_process_safe("var", "GIT_COMMITTER_IDENT")
        actor, timestamp, offset = parse_actor_and_date("committer " + identity)
        git_date = identity.rsplit("> ", 1)[1]
        # Git's reflog messages are single lines with collapsed ASCII whitespace.
        message = re.sub(r"[ \t\r\n\v\f]+", " ", message.split("\n", 1)[0]).strip(" ")
        ref.repo.git._call_process_safe(
            "reflog",
            "write",
            "--",
            ref.path,
            oldbinsha.hex(),
            newbinsha.hex(),
            message,
            env={"GIT_COMMITTER_NAME": actor.name, "GIT_COMMITTER_EMAIL": actor.email, "GIT_COMMITTER_DATE": git_date},
        )
        return RefLogEntry(newbinsha.hex(), actor, (timestamp, offset), message)
