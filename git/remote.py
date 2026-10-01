# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Module implementing a remote object allowing easy access to git remotes."""

__all__ = ["RemoteProgress", "PushInfo", "FetchInfo", "Remote"]

import logging
import re

from git.cmd import Git, handle_process_output
from git.compat import force_text
from git.config import GitConfigParser, SectionConstraint, cp
from git.refs import Reference, RemoteReference, SymbolicReference, TagReference
from git.util import (
    CallableRemoteProgress,
    IterableList,
    IterableObj,
    LazyMixin,
    RemoteProgress,
)

# typing-------------------------------------------------------

from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    NoReturn,
    Optional,
    Sequence,
    TYPE_CHECKING,
    TypeVar,
    Union,
    cast,
    overload,
)

from git.types import AnyGitObject, Literal, PathLike

if TYPE_CHECKING:
    from git.objects.commit import Commit
    from git.objects.submodule.base import UpdateProgress
    from git.repo.base import Repo

_T_RemoteName = TypeVar("_T_RemoteName", bound=Union[str, "Remote"])

flagKeyLiteral = Literal[" ", "!", "+", "-", "*", "=", "t", "?"]

# -------------------------------------------------------------

_logger = logging.getLogger(__name__)

# { Utilities


def add_progress(
    kwargs: Any,
    git: Git,
    progress: Union[RemoteProgress, "UpdateProgress", Callable[..., RemoteProgress], None],
) -> Any:
    """Add the ``--progress`` flag to the given `kwargs` dict if supported by the git
    command.

    :note:
        If the actual progress in the given progress instance is not given, we do not
        request any progress.

    :return:
        Possibly altered `kwargs`
    """
    if progress is not None:
        v = git.version_info[:2]
        if v >= (1, 7):
            kwargs["progress"] = True
        # END handle --progress
    # END handle progress
    return kwargs


# } END utilities


@overload
def to_progress_instance(progress: None) -> RemoteProgress: ...


@overload
def to_progress_instance(progress: Callable[..., Any]) -> CallableRemoteProgress: ...


@overload
def to_progress_instance(progress: RemoteProgress) -> RemoteProgress: ...


def to_progress_instance(
    progress: Union[Callable[..., Any], RemoteProgress, None],
) -> Union[RemoteProgress, CallableRemoteProgress]:
    """Given the `progress` return a suitable object derived from
    :class:`~git.util.RemoteProgress`."""
    # New API only needs progress as a function.
    if callable(progress):
        return CallableRemoteProgress(progress)

    # Where None is passed create a parser that eats the progress.
    elif progress is None:
        return RemoteProgress()

    # Assume its the old API with an instance of RemoteProgress.
    return progress


class PushInfo(IterableObj):
    """
    Carries information about the result of a push operation of a single head::

        info = remote.push()[0]
        info.flags          # bitflags providing more information about the result
        info.local_ref      # Reference pointing to the local reference that was pushed
                            # It is None if the ref was deleted.
        info.remote_ref_string # path to the remote reference located on the remote side
        info.remote_ref # Remote Reference on the local side corresponding to
                        # the remote_ref_string. It can be a TagReference as well.
        info.old_commit # commit at which the remote_ref was standing before we pushed
                        # it to local_ref.commit. Will be None if an error was indicated
        info.summary    # summary line providing human readable english text about the push
    """

    __slots__ = (
        "local_ref",
        "remote_ref_string",
        "flags",
        "_old_commit_sha",
        "_remote",
        "summary",
    )

    _id_attribute_ = "pushinfo"

    (
        NEW_TAG,
        NEW_HEAD,
        NO_MATCH,
        REJECTED,
        REMOTE_REJECTED,
        REMOTE_FAILURE,
        DELETED,
        FORCED_UPDATE,
        FAST_FORWARD,
        UP_TO_DATE,
        ERROR,
    ) = [1 << x for x in range(11)]

    _flag_map = {
        "X": NO_MATCH,
        "-": DELETED,
        "*": 0,
        "+": FORCED_UPDATE,
        " ": FAST_FORWARD,
        "=": UP_TO_DATE,
        "!": ERROR,
    }

    def __init__(
        self,
        flags: int,
        local_ref: Union[SymbolicReference, None],
        remote_ref_string: str,
        remote: "Remote",
        old_commit: Optional[str] = None,
        summary: str = "",
    ) -> None:
        """Initialize a new instance.

        local_ref: HEAD | Head | RemoteReference | TagReference | Reference | SymbolicReference | None
        """
        self.flags = flags
        self.local_ref = local_ref
        self.remote_ref_string = remote_ref_string
        self._remote = remote
        self._old_commit_sha = old_commit
        self.summary = summary

    @property
    def old_commit(self) -> Union["Commit", None]:
        return self._old_commit_sha and self._remote.repo.commit(self._old_commit_sha) or None

    @property
    def remote_ref(self) -> Union[RemoteReference, TagReference]:
        """
        :return:
            Remote :class:`~git.refs.reference.Reference` or
            :class:`~git.refs.tag.TagReference` in the local repository corresponding to
            the :attr:`remote_ref_string` kept in this instance.
        """
        # Translate heads to a local remote. Tags stay as they are.
        if self.remote_ref_string.startswith("refs/tags"):
            return TagReference(self._remote.repo, self.remote_ref_string)
        elif self.remote_ref_string.startswith("refs/heads"):
            remote_ref = Reference(self._remote.repo, self.remote_ref_string)
            return RemoteReference(
                self._remote.repo,
                "refs/remotes/%s/%s" % (str(self._remote), remote_ref.name),
            )
        else:
            raise ValueError("Could not handle remote ref: %r" % self.remote_ref_string)
        # END

    @classmethod
    def _from_line(cls, remote: "Remote", line: str) -> "PushInfo":
        """Create a new :class:`PushInfo` instance as parsed from line which is expected
        to be like refs/heads/master:refs/heads/master 05d2687..1d0568e as bytes."""
        control_character, from_to, summary = line.split("\t", 3)
        flags = 0

        # Control character handling
        try:
            flags |= cls._flag_map[control_character]
        except KeyError as e:
            raise ValueError("Control character %r unknown as parsed from line %r" % (control_character, line)) from e
        # END handle control character

        # from_to handling
        from_ref_string, to_ref_string = from_to.split(":")
        if flags & cls.DELETED:
            from_ref: Union[SymbolicReference, None] = None
        else:
            if from_ref_string == "(delete)":
                from_ref = None
            else:
                from_ref = Reference.from_path(remote.repo, from_ref_string)

        # Commit handling, could be message or commit info
        old_commit: Optional[str] = None
        if summary.startswith("["):
            if "[rejected]" in summary:
                flags |= cls.REJECTED
            elif "[remote rejected]" in summary:
                flags |= cls.REMOTE_REJECTED
            elif "[remote failure]" in summary:
                flags |= cls.REMOTE_FAILURE
            elif "[no match]" in summary:
                flags |= cls.ERROR
            elif "[new tag]" in summary:
                flags |= cls.NEW_TAG
            elif "[new branch]" in summary:
                flags |= cls.NEW_HEAD
            # `uptodate` encoded in control character
        else:
            # Fast-forward or forced update - was encoded in control character,
            # but we parse the old and new commit.
            split_token = "..."
            if control_character == " ":
                split_token = ".."
            old_sha, _new_sha = summary.split(" ")[0].split(split_token)
            # Have to use constructor here as the sha usually is abbreviated.
            old_commit = old_sha
        # END message handling

        return PushInfo(flags, from_ref, to_ref_string, remote, old_commit, summary)

    @classmethod
    def iter_items(cls, repo: "Repo", *args: Any, **kwargs: Any) -> NoReturn:  # -> Iterator['PushInfo']:
        raise NotImplementedError


class PushInfoList(IterableList[PushInfo]):
    """:class:`~git.util.IterableList` of :class:`PushInfo` objects."""

    def __new__(cls) -> "PushInfoList":
        return cast(PushInfoList, IterableList.__new__(cls, "push_infos"))

    def __init__(self) -> None:
        super().__init__("push_infos")
        self.error: Optional[Exception] = None

    def raise_if_error(self) -> None:
        """Raise an exception if any ref failed to push."""
        if self.error:
            raise self.error


class FetchInfo(IterableObj):
    """
    Carries information about the results of a fetch operation of a single head::

     info = remote.fetch()[0]
     info.ref           # Symbolic Reference or RemoteReference to the changed
                        # remote head or FETCH_HEAD
     info.flags         # additional flags to be & with enumeration members,
                        # i.e. info.flags & info.REJECTED
                        # is 0 if ref is SymbolicReference
     info.note          # additional notes given by git-fetch intended for the user
     info.old_commit    # if info.flags & info.FORCED_UPDATE|info.FAST_FORWARD,
                        # field is set to the previous location of ref, otherwise None
     info.remote_ref_path # The path from which we fetched on the remote. It's the remote's version of our info.ref
    """

    __slots__ = ("ref", "old_commit", "flags", "note", "remote_ref_path")

    _id_attribute_ = "fetchinfo"

    (
        NEW_TAG,
        NEW_HEAD,
        HEAD_UPTODATE,
        TAG_UPDATE,
        REJECTED,
        FORCED_UPDATE,
        FAST_FORWARD,
        ERROR,
    ) = [1 << x for x in range(8)]

    _re_fetch_result = re.compile(r"^ *(?:.{0,3})(.) (\[[\w \.$@]+\]|[\w\.$@]+) +(.+) -> ([^ ]+)(    \(.*\)?$)?")

    _flag_map: Dict[flagKeyLiteral, int] = {
        "!": ERROR,
        "+": FORCED_UPDATE,
        "*": 0,
        "=": HEAD_UPTODATE,
        " ": FAST_FORWARD,
        "-": TAG_UPDATE,
    }

    @classmethod
    def refresh(cls) -> Literal[True]:
        """Update information about which :manpage:`git-fetch(1)` flags are supported
        by the git executable being used.

        Called by the :func:`git.refresh` function in the top level ``__init__``.
        """
        cls._flag_map["t"] = cls.TAG_UPDATE
        cls._flag_map["-"] = 0

        return True

    def __init__(
        self,
        ref: SymbolicReference,
        flags: int,
        note: str = "",
        old_commit: Union[AnyGitObject, None] = None,
        remote_ref_path: Optional[PathLike] = None,
    ) -> None:
        """Initialize a new instance."""
        self.ref = ref
        self.flags = flags
        self.note = note
        self.old_commit = old_commit
        self.remote_ref_path = remote_ref_path

    def __str__(self) -> str:
        return self.name

    @property
    def name(self) -> str:
        """:return: Name of our remote ref"""
        return self.ref.name

    @property
    def commit(self) -> "Commit":
        """:return: Commit of our remote ref"""
        return self.ref.commit

    @staticmethod
    def _display_ref(path: str) -> str:
        for prefix in ("refs/heads/", "refs/tags/", "refs/remotes/"):
            if path.startswith(prefix):
                return path[len(prefix) :]
        return path

    @classmethod
    def _from_line(cls, repo: "Repo", line: str, refspecs: Sequence[str] = (), refs: Sequence[str] = ()) -> "FetchInfo":
        """Decode Git's full verbose fetch output without reading FETCH_HEAD."""
        match = cls._re_fetch_result.match(line)
        if match is None:
            raise ValueError("Failed to parse fetch output: %r" % line)
        control, operation, source, destination, note = match.groups()
        source = source.strip()
        if control not in cls._flag_map:
            raise ValueError("Unknown fetch status: %r" % control)
        flags = cls._flag_map[cast(flagKeyLiteral, control)]
        if "rejected" in operation:
            flags |= cls.REJECTED
        if "new tag" in operation:
            flags |= cls.NEW_TAG
        elif "new branch" in operation:
            flags |= cls.NEW_HEAD
        old_commit = None
        if control in (" ", "+"):
            old_commit = repo.rev_parse(operation.split("..", 1)[0])
        destination = destination.strip()
        if destination == "FETCH_HEAD":
            ref = SymbolicReference(repo, destination)
        else:
            candidates = set()
            for spec in refspecs:
                if spec.startswith("^") or ":" not in spec:
                    continue
                remote, local = spec.lstrip("+").split(":", 1)
                remote = cls._display_ref(remote)
                if "*" in remote:
                    prefix, suffix = remote.split("*", 1)
                    if not source.startswith(prefix) or not source.endswith(suffix):
                        continue
                    middle = source[len(prefix) : len(source) - len(suffix) if suffix else None]
                    local = local.replace("*", middle)
                elif remote != source:
                    continue
                if cls._display_ref(local) == destination:
                    candidates.add(local)
            if destination.startswith("refs/"):
                candidates = {destination}
            if not candidates:
                candidates = {path for path in refs if cls._display_ref(path) == destination}
            if len(candidates) > 1 and ("tag" in operation or control == "t"):
                candidates = {path for path in candidates if path.startswith("refs/tags/")}
            if len(candidates) != 1:
                raise ValueError("Cannot unambiguously resolve fetched reference %r" % destination)
            path = candidates.pop()
            ref = SymbolicReference.from_path(repo, path)
        return cls(ref, flags, (note or "").strip(), old_commit, source)

    @classmethod
    def iter_items(cls, repo: "Repo", *args: Any, **kwargs: Any) -> NoReturn:  # -> Iterator['FetchInfo']:
        raise NotImplementedError


Progress = Union[RemoteProgress, "UpdateProgress", Callable[..., RemoteProgress], None]


class Remote(LazyMixin, IterableObj):
    """Provides easy read and write access to a git remote.

    Everything not part of this interface is considered an option for the current
    remote, allowing constructs like ``remote.pushurl`` to query the pushurl.

    :note:
        When querying configuration, the configuration accessor will be cached to speed
        up subsequent accesses.
    """

    __slots__ = ("repo", "name", "_config_reader")

    _id_attribute_ = "name"

    unsafe_git_fetch_options = [
        # This option allows users to execute arbitrary commands.
        # https://git-scm.com/docs/git-fetch#Documentation/git-fetch.txt---upload-packltupload-packgt
        "--upload-pack",
    ]
    unsafe_git_pull_options = [
        # This option allows users to execute arbitrary commands.
        # https://git-scm.com/docs/git-pull#Documentation/git-pull.txt---upload-packltupload-packgt
        "--upload-pack"
    ]
    unsafe_git_push_options = [
        # This option allows users to execute arbitrary commands.
        # https://git-scm.com/docs/git-push#Documentation/git-push.txt---execltgit-receive-packgt
        "--receive-pack",
        "--exec",
    ]

    url: str  # Obtained dynamically from _config_reader. See __getattr__ below.
    """The URL configured for the remote."""

    def __init__(self, repo: "Repo", name: str) -> None:
        """Initialize a remote instance.

        :param repo:
            The repository we are a remote of.

        :param name:
            The name of the remote, e.g. ``origin``.
        """
        self.repo = repo
        self.name = name

    def __getattr__(self, attr: str) -> Any:
        """Allows to call this instance like ``remote.special(*args, **kwargs)`` to
        call ``git remote special self.name``."""
        if attr == "_config_reader":
            return super().__getattr__(attr)

        # Sometimes, probably due to a bug in Python itself, we are being called even
        # though a slot of the same name exists.
        try:
            return self._config_reader.get(attr)
        except cp.NoOptionError:
            return super().__getattr__(attr)
        # END handle exception

    def _config_section_name(self) -> str:
        return GitConfigParser._public_section("remote." + self.name)

    def _set_cache_(self, attr: str) -> None:
        if attr == "_config_reader":
            # NOTE: This is cached as __getattr__ is overridden to return remote config
            # values implicitly, such as in print(r.pushurl).
            self._config_reader = SectionConstraint(
                self.repo.config_reader("repository"),
                self._config_section_name(),
            )
        else:
            super()._set_cache_(attr)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return '<git.%s "%s">' % (self.__class__.__name__, self.name)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.name == other.name

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash(self.name)

    def exists(self) -> bool:
        """
        :return:
            ``True`` if this is a valid, existing remote.
            Valid remotes have an entry in the repository's configuration.
        """
        try:
            self.config_reader.get("url")
            return True
        except cp.NoOptionError:
            # We have the section at least...
            return True
        except cp.NoSectionError:
            return False

    @classmethod
    def iter_items(cls, repo: "Repo", *args: Any, **kwargs: Any) -> Iterator["Remote"]:
        """:return: Iterator yielding :class:`Remote` objects of the given repository"""
        for section in repo.config_reader("repository").sections():
            if not section.lower().startswith("remote "):
                continue
            lbound = section.find('"')
            rbound = section.rfind('"')
            if lbound == -1 or rbound == -1:
                raise ValueError("Remote-Section has invalid format: %r" % section)
            yield Remote(repo, GitConfigParser._section_name(section).split(".", 1)[1])
        # END for each configuration section

    def set_url(
        self, new_url: str, old_url: Optional[str] = None, allow_unsafe_protocols: bool = False, **kwargs: Any
    ) -> "Remote":
        """Configure URLs on current remote (cf. command ``git remote set-url``).

        This command manages URLs on the remote.

        :param new_url:
            String being the URL to add as an extra remote URL.

        :param old_url:
            When set, replaces this URL with `new_url` for the remote.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :return:
            self
        """
        Git._check_operand(self.name, "remote name")
        if not allow_unsafe_protocols:
            Git.check_unsafe_protocols(new_url)
        Git._check_operand(new_url, "remote URL")
        if old_url is not None:
            Git._check_operand(old_url, "old remote URL")
        scmd = "set-url"
        kwargs["insert_kwargs_after"] = scmd
        if old_url:
            self.repo.git._call_process_safe("remote", scmd, "--", self.name, new_url, old_url, **kwargs)
        else:
            self.repo.git._call_process_safe("remote", scmd, "--", self.name, new_url, **kwargs)
        return self

    def add_url(self, url: str, allow_unsafe_protocols: bool = False, **kwargs: Any) -> "Remote":
        """Adds a new url on current remote (special case of ``git remote set-url``).

        This command adds new URLs to a given remote, making it possible to have
        multiple URLs for a single remote.

        :param url:
            String being the URL to add as an extra remote URL.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :return:
            self
        """
        return self.set_url(url, add=True, allow_unsafe_protocols=allow_unsafe_protocols)

    def delete_url(self, url: str, **kwargs: Any) -> "Remote":
        """Deletes a new url on current remote (special case of ``git remote set-url``).

        This command deletes new URLs to a given remote, making it possible to have
        multiple URLs for a single remote.

        :param url:
            String being the URL to delete from the remote.

        :return:
            self
        """
        return self.set_url(url, delete=True)

    @property
    def urls(self) -> Iterator[str]:
        """:return: Iterator yielding all configured URL targets on a remote as strings"""
        yield from self.repo.git._call_process_safe("remote", "get-url", "--all", "--", self.name).splitlines()

    @property
    def refs(self) -> IterableList[RemoteReference]:
        """
        :return:
            :class:`~git.util.IterableList` of :class:`~git.refs.remote.RemoteReference`
            objects.

            It is prefixed, allowing you to omit the remote path portion, e.g.::

                remote.refs.master  # yields RemoteReference('/refs/remotes/origin/master')
        """
        out_refs: IterableList[RemoteReference] = IterableList(RemoteReference._id_attribute_, "%s/" % self.name)
        out_refs.extend(RemoteReference.list_items(self.repo, remote=self.name))
        return out_refs

    @property
    def stale_refs(self) -> IterableList[Reference]:
        """
        :return:
            :class:`~git.util.IterableList` of :class:`~git.refs.remote.RemoteReference`
            objects that do not have a corresponding head in the remote reference
            anymore as they have been deleted on the remote side, but are still
            available locally.

            The :class:`~git.util.IterableList` is prefixed, hence the 'origin' must be
            omitted. See :attr:`refs` property for an example.

            To make things more complicated, it can be possible for the list to include
            other kinds of references, for example, tag references, if these are stale
            as well. This is a fix for the issue described here:
            https://github.com/gitpython-developers/GitPython/issues/260
        """
        out_refs: IterableList[Reference] = IterableList(RemoteReference._id_attribute_, "%s/" % self.name)
        for line in self.repo.git._call_process_safe(
            "remote", "prune", "--dry-run", "--", self, _allow_network=True
        ).splitlines()[2:]:
            # expecting
            # * [would prune] origin/new_branch
            token = " * [would prune] "
            if not line.startswith(token):
                continue
            ref_name = line.replace(token, "")
            # Sometimes, paths start with a full ref name, like refs/tags/foo. See #260.
            if ref_name.startswith(Reference._common_path_default + "/"):
                out_refs.append(Reference.from_path(self.repo, ref_name))
            else:
                fqhn = "%s/%s" % (RemoteReference._common_path_default, ref_name)
                out_refs.append(RemoteReference(self.repo, fqhn))
            # END special case handling
        # END for each line
        return out_refs

    @classmethod
    def create(cls, repo: "Repo", name: str, url: str, allow_unsafe_protocols: bool = False, **kwargs: Any) -> "Remote":
        """Create a new remote to the given repository.

        :param repo:
            Repository instance that is to receive the new remote.

        :param name:
            Desired name of the remote.

        :param url:
            URL which corresponds to the remote's name.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param kwargs:
            Additional arguments to be passed to the ``git remote add`` command.

        :return:
            New :class:`Remote` instance

        :raise git.exc.GitCommandError:
            In case an origin with that name already exists.
        """
        Git._check_operand(name, "remote name")
        Git._check_operand(url, "remote URL")
        scmd = "add"
        kwargs["insert_kwargs_after"] = scmd
        url = Git.polish_url(url, expand_vars=False)
        if not allow_unsafe_protocols:
            Git.check_unsafe_protocols(url)
        repo.git._call_process_safe("remote", scmd, "--", name, url, **kwargs)
        return cls(repo, name)

    # `add` is an alias.
    @classmethod
    def add(cls, repo: "Repo", name: str, url: str, **kwargs: Any) -> "Remote":
        return cls.create(repo, name, url, **kwargs)

    @classmethod
    def remove(cls, repo: "Repo", name: _T_RemoteName) -> _T_RemoteName:
        """Remove the remote with the given name.

        :return:
            The passed remote name to remove
        """
        repo.git._call_process_safe("remote", "rm", "--", Git._check_operand(name, "remote name"))
        remote = name
        if isinstance(remote, cls):
            remote._clear_cache()
        return name

    @classmethod
    def rm(cls, repo: "Repo", name: _T_RemoteName) -> _T_RemoteName:
        """Alias of remove.
        Remove the remote with the given name.

        :return:
            The passed remote name to remove
        """
        return cls.remove(repo, name)

    def rename(self, new_name: str) -> "Remote":
        """Rename self to the given `new_name`.

        :return:
            self
        """
        if self.name == new_name:
            return self

        self.repo.git._call_process_safe(
            "remote", "rename", "--", self.name, Git._check_operand(new_name, "remote name")
        )
        self.name = new_name
        self._clear_cache()

        return self

    def update(self, **kwargs: Any) -> "Remote":
        """Fetch all changes for this remote, including new branches which will be
        forced in (in case your local remote branch is not part the new remote branch's
        ancestry anymore).

        :param kwargs:
            Additional arguments passed to ``git remote update``.

        :return:
            self
        """
        # Like pull, remote update forwards operands to fetch without `--`.
        Git._check_operand(self.name, "remote name")
        scmd = "update"
        kwargs["insert_kwargs_after"] = scmd
        self.repo.git._call_process_safe("remote", scmd, "--", self.name, _allow_network=True, **kwargs)
        return self

    def _get_fetch_info_from_stderr(
        self,
        proc: "Git.AutoInterrupt",
        progress: Progress,
        kill_after_timeout: Union[None, float] = None,
        refspecs: Sequence[str] = (),
    ) -> IterableList["FetchInfo"]:
        progress = to_progress_instance(progress)

        # Skip first line as it is some remote info we are not interested in.
        output: IterableList["FetchInfo"] = IterableList("name")

        # Lines which are no progress are fetch info lines.
        # This also waits for the command to finish.
        # Skip some progress lines that don't provide relevant information.
        fetch_info_lines = []
        # Basically we want all fetch info lines which appear to be in regular form, and
        # thus have a command character. Everything else we ignore.
        cmds = set(FetchInfo._flag_map.keys())

        progress_handler = progress.new_message_handler()
        handle_process_output(
            proc,
            None,
            progress_handler,
            finalizer=None,
            decode_streams=False,
            kill_after_timeout=kill_after_timeout,
        )

        stderr_text = "\n".join(progress.error_lines)
        proc.wait(stderr=stderr_text)
        if stderr_text:
            _logger.warning("Error lines received while fetching: %s", stderr_text)

        in_submodule = False
        for line in progress.other_lines:
            line = force_text(line)
            if line.startswith("Fetching submodule "):
                in_submodule = True
            if in_submodule:
                continue
            for cmd in cmds:
                if len(line) > 1 and line[0] == " " and line[1] == cmd:
                    fetch_info_lines.append(line)
                    continue

        refs = self.repo.git._call_process_safe("for_each_ref", "--format=%(refname)").splitlines()
        try:
            configured = self.config_reader.config.get_values(self._config_section_name(), "fetch")
        except (cp.NoSectionError, cp.NoOptionError):
            configured = []
        specs = [*refspecs, *configured]
        for line in fetch_info_lines:
            try:
                output.append(FetchInfo._from_line(self.repo, line, specs, refs))
            except ValueError as exc:
                _logger.warning("Cannot decode fetch result %r: %s", line, exc)
        # A source-only refspec reports both FETCH_HEAD and any opportunistic
        # tracking-ref update. Preserve one result for the requested source.
        fetched_sources = {info.remote_ref_path for info in output if info.ref.path == "FETCH_HEAD"}
        output[:] = [
            info for info in output if info.ref.path == "FETCH_HEAD" or info.remote_ref_path not in fetched_sources
        ]
        return output

    def _get_push_info(
        self,
        proc: "Git.AutoInterrupt",
        progress: Union[Callable[..., Any], RemoteProgress, None],
        kill_after_timeout: Union[None, float] = None,
    ) -> PushInfoList:
        progress = to_progress_instance(progress)

        # Read progress information from stderr.
        # We hope stdout can hold all the data, it should...
        # Read the lines manually as it will use carriage returns between the messages
        # to override the previous one. This is why we read the bytes manually.
        progress_handler = progress.new_message_handler()
        output: PushInfoList = PushInfoList()

        def stdout_handler(line: str) -> None:
            try:
                output.append(PushInfo._from_line(self, line))
            except ValueError:
                # If an error happens, additional info is given which we parse below.
                pass

        handle_process_output(
            proc,
            stdout_handler,
            progress_handler,
            finalizer=None,
            decode_streams=False,
            kill_after_timeout=kill_after_timeout,
        )
        stderr_text = "\n".join(progress.error_lines)
        try:
            proc.wait(stderr=stderr_text)
        except Exception as e:
            # This is different than fetch (which fails if there is any stderr
            # even if there is an output).
            if not output:
                raise
            elif stderr_text or proc._timeout_error:
                if stderr_text:
                    _logger.warning("Error lines received while pushing: %s", stderr_text)
                output.error = e

        return output

    def _assert_refspec(self) -> None:
        """Turns out we can't deal with remotes if the refspec is missing."""
        config = self.config_reader
        unset = "placeholder"
        try:
            if config.get_value("fetch", default=unset) is unset:
                msg = "Remote '%s' has no refspec set.\n"
                msg += "You can set it as follows:"
                msg += " 'git config --add \"remote.%s.fetch +refs/heads/*:refs/heads/*\"'."
                raise AssertionError(msg % (self.name, self.name))
        finally:
            config.release()

    def fetch(
        self,
        refspec: Union[str, List[str], None] = None,
        progress: Progress = None,
        verbose: bool = True,
        kill_after_timeout: Union[None, float] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> IterableList[FetchInfo]:
        """Fetch the latest changes for this remote.

        :param refspec:
            A "refspec" is used by fetch and push to describe the mapping
            between remote ref and local ref. They are combined with a colon in
            the format ``<src>:<dst>``, preceded by an optional plus sign, ``+``.
            For example: ``git fetch $URL refs/heads/master:refs/heads/origin`` means
            "grab the master branch head from the $URL and store it as my origin
            branch head". And ``git push $URL refs/heads/master:refs/heads/to-upstream``
            means "publish my master branch head as to-upstream branch at $URL".
            See also :manpage:`git-push(1)`.

            Taken from the git manual, :manpage:`gitglossary(7)`.

            Fetch supports multiple refspecs (as the underlying :manpage:`git-fetch(1)`
            does) - supplying a list rather than a string for 'refspec' will make use of
            this facility.

        :param progress:
            See the :meth:`push` method.

        :param verbose:
            Boolean for verbose output.

        :param kill_after_timeout:
            To specify a timeout in seconds for the git command, after which the process
            should be killed. It is set to ``None`` by default.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param allow_unsafe_options:
            Allow unsafe options to be used, like ``--upload-pack``.

        :param kwargs:
            Additional arguments to be passed to :manpage:`git-fetch(1)`.

        :return:
            IterableList(FetchInfo, ...) list of :class:`FetchInfo` instances providing
            detailed information about the fetch results

        :note:
            As fetch does not provide progress information to non-ttys, we cannot make
            it available here unfortunately as in the :meth:`push` method.
        """
        if refspec is None:
            # No argument refspec, then ensure the repo's config has a fetch refspec.
            self._assert_refspec()

        Git._check_operand(self.name, "remote name")
        kwargs = add_progress(kwargs, self.repo.git, progress)
        if isinstance(refspec, list):
            args: Sequence[Optional[str]] = refspec
        else:
            args = [refspec]

        if not allow_unsafe_protocols:
            self.repo.git._check_unsafe_protocols_in_args([self, *args], kwargs)

        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=self.unsafe_git_fetch_options,
            )

        proc = self.repo.git._call_process_safe(
            "fetch",
            "--",
            self,
            *args,
            as_process=True,
            with_stdout=False,
            universal_newlines=True,
            v=bool(verbose),
            _allow_network=True,
            _config=("fetch.output=full", "core.abbrev=no"),
            **kwargs,
        )
        res = self._get_fetch_info_from_stderr(
            proc, progress, kill_after_timeout=kill_after_timeout, refspecs=Git._unpack_args(refspec or [])
        )
        if hasattr(self.repo.odb, "update_cache"):
            self.repo.odb.update_cache()
        return res

    def pull(
        self,
        refspec: Union[str, List[str], None] = None,
        progress: Progress = None,
        kill_after_timeout: Union[None, float] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> IterableList[FetchInfo]:
        """Pull changes from the given branch, being the same as a fetch followed by a
        merge of branch with your local branch.

        :param refspec:
            See :meth:`fetch` method. Values starting with ``-`` are rejected,
            even when ``allow_unsafe_options`` is enabled. Pass options as keywords.

        :param progress:
            See :meth:`push` method.

        :param kill_after_timeout:
            See :meth:`fetch` method.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param allow_unsafe_options:
            Allow unsafe options to be used, like ``--upload-pack``.

        :param kwargs:
            Additional arguments to be passed to :manpage:`git-pull(1)`.

        :return:
            Please see :meth:`fetch` method.
        """
        if refspec is None:
            # No argument refspec, then ensure the repo's config has a fetch refspec.
            self._assert_refspec()
        Git._check_operand(self.name, "remote name")
        kwargs = add_progress(kwargs, self.repo.git, progress)

        refspec = Git._unpack_args(refspec or [])
        # Git pull forwards these operands to fetch without preserving `--`.
        # Reject every option-shaped operand, including with unsafe options enabled:
        # opting into an explicit option must not turn a refspec into an option.
        for operand in [self.name, *refspec]:
            Git._check_operand(operand, "remote name or pull refspec")
        if not allow_unsafe_protocols:
            self.repo.git._check_unsafe_protocols_in_args([self, *refspec], kwargs)

        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=self.unsafe_git_pull_options,
            )

        proc = self.repo.git._call_process_safe(
            "pull",
            "--",
            self,
            refspec,
            with_stdout=False,
            as_process=True,
            universal_newlines=True,
            v=True,
            _allow_network=True,
            _config=("fetch.output=full", "core.abbrev=no"),
            **kwargs,
        )
        res = self._get_fetch_info_from_stderr(
            proc, progress, kill_after_timeout=kill_after_timeout, refspecs=Git._unpack_args(refspec or [])
        )
        if hasattr(self.repo.odb, "update_cache"):
            self.repo.odb.update_cache()
        return res

    def push(
        self,
        refspec: Union[str, List[str], None] = None,
        progress: Progress = None,
        kill_after_timeout: Union[None, float] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> PushInfoList:
        """Push changes from source branch in refspec to target branch in refspec.

        :param refspec:
            See :meth:`fetch` method.

        :param progress:
            Can take one of many value types:

            * ``None``, to discard progress information.
            * A function (callable) that is called with the progress information.
              Signature: ``progress(op_code, cur_count, max_count=None, message='')``.
              See :meth:`RemoteProgress.update <git.util.RemoteProgress.update>` for a
              description of all arguments given to the function.
            * An instance of a class derived from :class:`~git.util.RemoteProgress` that
              overrides the
              :meth:`RemoteProgress.update <git.util.RemoteProgress.update>` method.

        :note:
            No further progress information is returned after push returns.

        :param kill_after_timeout:
            To specify a timeout in seconds for the git command, after which the process
            should be killed. It is set to ``None`` by default.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param allow_unsafe_options:
            Allow unsafe options to be used, like ``--receive-pack``.

        :param kwargs:
            Additional arguments to be passed to :manpage:`git-push(1)`.

        :return:
            A :class:`PushInfoList` object, where each list member represents an
            individual head which had been updated on the remote side.

            If the push contains rejected heads, these will have the
            :const:`PushInfo.ERROR` bit set in their flags.

            If the operation fails completely, the length of the returned
            :class:`PushInfoList` will be 0.

            Call :meth:`~PushInfoList.raise_if_error` on the returned object to raise on
            any failure.
        """
        Git._check_operand(self.name, "remote name")
        kwargs = add_progress(kwargs, self.repo.git, progress)

        refspec = Git._unpack_args(refspec or [])
        if not allow_unsafe_protocols:
            self.repo.git._check_unsafe_protocols_in_args([self, *refspec], kwargs)

        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=self.unsafe_git_push_options,
            )

        proc = self.repo.git._call_process_safe(
            "push",
            "--",
            self,
            refspec,
            porcelain=True,
            _allow_network=True,
            as_process=True,
            universal_newlines=True,
            kill_after_timeout=kill_after_timeout,
            **kwargs,
        )
        return self._get_push_info(proc, progress, kill_after_timeout=kill_after_timeout)

    @property
    def config_reader(self) -> SectionConstraint[GitConfigParser]:
        """
        :return:
            :class:`~git.config.GitConfigParser` compatible object able to read options
            for only our remote. Hence you may simply type ``config.get("pushurl")`` to
            obtain the information.
        """
        return self._config_reader

    def _clear_cache(self) -> None:
        try:
            del self._config_reader
        except AttributeError:
            pass
        # END handle exception

    @property
    def config_writer(self) -> SectionConstraint:
        """
        :return:
            :class:`~git.config.GitConfigParser`-compatible object able to write options
            for this remote.

        :note:
            Git locks each configuration mutation independently.
            To assure consistent results, you should only query options through the
            writer. Once you are done writing, you are free to use the config reader
            once again.
        """
        writer = self.repo.config_writer()

        # Clear our cache to ensure we re-read the possibly changed configuration.
        self._clear_cache()
        return SectionConstraint(writer, self._config_section_name())
