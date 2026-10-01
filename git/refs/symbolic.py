# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

__all__ = ["SymbolicReference"]

import os
from functools import lru_cache
import tempfile

from gitdb.exc import BadName, BadObject

from git.cmd import Git
from git.exc import GitCommandError, UnsafeOptionError
from git.objects.base import Object
from git.objects.commit import Commit
from git.refs.log import RefLog
from git.util import (
    hex_to_bin,
    join_path_native,
)

# typing ------------------------------------------------------------------

from typing import (
    Any,
    Dict,
    Iterator,
    TYPE_CHECKING,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

from git.types import AnyGitObject, PathLike

if TYPE_CHECKING:
    from git.refs.log import RefLogEntry
    from git.refs.reference import Reference
    from git.repo import Repo


T_References = TypeVar("T_References", bound="SymbolicReference")

# ------------------------------------------------------------------------------


def _git_dir(repo: "Repo", path: Union[PathLike, None]) -> PathLike:
    """Find the git dir that is appropriate for the path."""
    name = f"{path}"
    if not name.startswith("refs/") or name.startswith(("refs/bisect/", "refs/worktree/", "refs/rewritten/")):
        return repo.git_dir
    return repo.common_dir


class SymbolicReference:
    """A reference that can point to another reference or be detached.

    An attached :class:`~git.refs.head.HEAD` usually points to a
    :class:`~git.refs.head.Head`, which itself specifies a commit. A detached
    :class:`~git.refs.head.HEAD` points directly to a commit instead.

    Use :attr:`commit` to access the commit in either case, and :attr:`reference`
    to access the target reference when attached.
    """

    __slots__ = ("repo", "path")

    _resolve_ref_on_create = False
    _points_to_commits_only = True
    _common_path_default = ""
    _remote_common_path_default = "refs/remotes"
    _id_attribute_ = "name"
    # Match Git's SYMREF_MAXDEPTH, counting the terminal reference as well.
    _max_symref_depth = 5

    def __init__(self, repo: "Repo", path: PathLike, check_path: bool = False) -> None:
        self.repo = repo
        self.path: PathLike = path

    def __str__(self) -> str:
        return os.fspath(self.path)

    def __repr__(self) -> str:
        return '<git.%s "%s">' % (self.__class__.__name__, self.path)

    def __eq__(self, other: object) -> bool:
        if hasattr(other, "path"):
            other = cast(SymbolicReference, other)
            return self.path == other.path
        return False

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash(self.path)

    @property
    def name(self) -> str:
        """
        :return:
            In case of symbolic references, the shortest assumable name is the path
            itself.
        """
        return os.fspath(self.path)

    @property
    def abspath(self) -> PathLike:
        return join_path_native(_git_dir(self.repo, self.path), self.path)

    @staticmethod
    def _get_validated_path(base: PathLike, path: PathLike) -> str:
        path = os.fspath(path)
        base_path = os.path.realpath(os.fspath(base))
        abs_path = os.path.realpath(os.path.join(base_path, path))
        try:
            common_path = os.path.commonpath([base_path, abs_path])
        except ValueError as e:
            raise ValueError("Reference path %r escapes the repository" % path) from e
        if common_path != base_path:
            raise ValueError("Reference path %r escapes the repository" % path)
        return abs_path

    @classmethod
    def _get_validated_ref_path(cls, repo: "Repo", path: PathLike) -> str:
        """Return the absolute filesystem path for a ref after validating it."""
        cls._check_ref_name_valid(path)
        ref_path = os.fspath(path)
        return cls._get_validated_path(_git_dir(repo, ref_path), ref_path)

    @classmethod
    def dereference_recursive(cls, repo: "Repo", ref_path: Union[PathLike, None]) -> str:
        """
        :return:
            hexsha stored in the reference at the given `ref_path`, recursively
            dereferencing all intermediate references as required

        :param repo:
            The repository containing the reference at `ref_path`.

        :raise ValueError:
            If the reference is missing, invalid, or exceeds Git's limit of five
            references in a symbolic reference chain (including the terminal ref).
        """

        for _ in range(cls._max_symref_depth):
            hexsha, ref_path = cls._get_ref_info(repo, ref_path)
            if hexsha is not None:
                return hexsha
        # END recursive dereferencing
        raise ValueError("Too many levels of symbolic references at %r" % ref_path)

    @staticmethod
    def _check_ref_name_valid(ref_path: PathLike) -> None:
        """Validate reference names with Git, rejecting CLI control input first."""
        try:
            name = Git._check_operand(os.fspath(ref_path), "reference")
        except UnsafeOptionError as exc:
            raise ValueError("Invalid reference %r" % os.fspath(ref_path)) from exc
        SymbolicReference._check_ref_name_native(name, Git._refresh_token)

    @staticmethod
    @lru_cache(maxsize=512)
    def _check_ref_name_native(name: str, _refresh_token: object) -> None:
        # The grammar depends on Git's executable, not repository contents.
        # Filesystem containment remains checked separately on every operation.
        try:
            Git()._call_process_safe("check_ref_format", "--allow-onelevel", name)
        except GitCommandError as exc:
            raise ValueError("Invalid reference %r" % name) from exc

    @classmethod
    def _get_ref_info_helper(
        cls, repo: "Repo", ref_path: Union[PathLike, None]
    ) -> Union[Tuple[str, None], Tuple[None, str]]:
        if ref_path is None:
            raise ValueError("Reference does not exist")
        cls._get_validated_ref_path(repo, ref_path)
        path = os.fspath(ref_path)
        try:
            target = repo.git._call_process_safe("symbolic_ref", "--quiet", "--no-recurse", "--", path)
            cls._get_validated_ref_path(repo, target)
            return None, target
        except GitCommandError as exc:
            if exc.status != 1:
                raise ValueError("Invalid symbolic reference %r" % path) from exc
        try:
            oid = repo.git._call_process_safe("rev_parse", "--verify", "--end-of-options", path)
        except GitCommandError as exc:
            raise ValueError("Reference at %r does not exist or is invalid" % path) from exc
        if not repo.re_hexsha_only.fullmatch(oid):
            raise ValueError("Invalid object ID for reference %r" % path)
        return oid, None

    @classmethod
    def _get_ref_info(cls, repo: "Repo", ref_path: Union[PathLike, None]) -> Union[Tuple[str, None], Tuple[None, str]]:
        """
        :return:
            *(str(sha), str(target_ref_path))*, where:

            * *sha* is of the file at rela_path points to if available, or ``None``.
            * *target_ref_path* is the reference we point to, or ``None``.
        """
        return cls._get_ref_info_helper(repo, ref_path)

    def _get_object(self) -> AnyGitObject:
        """
        :return:
            The object our ref currently refers to. Refs can be cached, they will always
            point to the actual object as it gets re-created on each query.
        """
        # We have to be dynamic here as we may be a tag which can point to anything.
        # Our path will be resolved to the hexsha which will be used accordingly.
        return Object.new_from_sha(self.repo, hex_to_bin(self.dereference_recursive(self.repo, self.path)))

    def _get_commit(self) -> "Commit":
        """
        :return:
            :class:`~git.objects.commit.Commit` object we point to. This works for
            detached and non-detached :class:`SymbolicReference` instances. The symbolic
            reference will be dereferenced recursively.
        """
        obj = self._get_object()
        if obj.type == "tag":
            obj = obj.object
        # END dereference tag

        if obj.type != Commit.type:
            raise TypeError("Symbolic Reference pointed to object %r, commit was required" % obj)
        # END handle type
        return obj

    def set_commit(
        self,
        commit: Union[Commit, "SymbolicReference", str],
        logmsg: Union[str, None] = None,
    ) -> "SymbolicReference":
        """Like :meth:`set_object`, but restricts the type of object to be a
        :class:`~git.objects.commit.Commit`.

        :raise ValueError:
            If `commit` is not a :class:`~git.objects.commit.Commit` object, nor does it
            point to a commit.

        :return:
            self
        """
        # Check the type - assume the best if it is a base-string.
        invalid_type = False
        if isinstance(commit, Object):
            invalid_type = commit.type != Commit.type
        elif isinstance(commit, SymbolicReference):
            invalid_type = commit.object.type != Commit.type
        else:
            try:
                invalid_type = self.repo.rev_parse(commit).type != Commit.type
            except (BadObject, BadName) as e:
                raise ValueError("Invalid object: %s" % commit) from e
            # END handle exception
        # END verify type

        if invalid_type:
            raise ValueError("Need commit, got %r" % commit)
        # END handle raise

        # We leave strings to the rev-parse method below.
        self.set_object(commit, logmsg)

        return self

    def set_object(
        self,
        object: Union[AnyGitObject, "SymbolicReference", str],
        logmsg: Union[str, None] = None,
    ) -> "SymbolicReference":
        """Set the object we point to, possibly dereference our symbolic reference
        first. If the reference does not exist, it will be created.

        :param object:
            A refspec, a :class:`SymbolicReference` or an
            :class:`~git.objects.base.Object` instance.

            * :class:`SymbolicReference` instances will be dereferenced beforehand to
              obtain the git object they point to.
            * :class:`~git.objects.base.Object` instances must represent git objects
              (:class:`~git.types.AnyGitObject`).

        :param logmsg:
            If not ``None``, the message will be used in the reflog entry to be written.
            Otherwise Git applies its normal reflog policy.

        :note:
            Plain :class:`SymbolicReference` instances may not actually point to objects
            by convention.

        :return:
            self

        :raise ValueError:
            If the symbolic reference chain exceeds Git's limit of five references.
        """
        # Validate each link for repository path containment before Git updates
        # the chain. Git handles the actual dereferencing and transaction.
        ref_path: Union[PathLike, None] = self.path
        for _ in range(self._max_symref_depth):
            try:
                hexsha, ref_path = self._get_ref_info(self.repo, ref_path)
            except ValueError:
                break  # Allow creating an unborn terminal reference.
            if hexsha is not None:
                break
        else:
            raise ValueError("Too many levels of symbolic references at %r" % ref_path)

        self._get_validated_ref_path(self.repo, self.path)
        obj = self._resolve_object(object)
        options = []
        if logmsg is not None:
            if "\0" in logmsg:
                raise ValueError("Reflog messages must not contain NUL")
            options.append("--create-reflog")
            first_line = logmsg.split("\n", 1)[0]
            if first_line:
                options.extend(("-m", first_line))
        # Updating the original symbolic ref lets Git maintain the entire chain's
        # reflogs, including HEAD, in the same reference transaction.
        self.repo.git._call_process_safe(
            "update_ref",
            *options,
            "--",
            self.path,
            obj.hexsha,
            env=self._reflog_environment(obj) if logmsg is not None else {},
        )
        return self

    @property
    def commit(self) -> "Commit":
        """The commit this reference resolves to, whether detached or symbolic.

        For example, ``repo.head.commit.hexsha`` returns the current commit ID
        both on a branch and with a detached HEAD. HEAD must resolve to an
        existing commit; an unborn branch in an empty repository has none.

        Assigning updates the commit without changing whether this reference
        is detached.
        """
        return self._get_commit()

    @commit.setter
    def commit(self, commit: Union[Commit, "SymbolicReference", str]) -> "SymbolicReference":
        return self.set_commit(commit)

    @property
    def object(self) -> AnyGitObject:
        """Return the object our ref currently refers to"""
        return self._get_object()

    @object.setter
    def object(self, object: Union[AnyGitObject, "SymbolicReference", str]) -> "SymbolicReference":
        return self.set_object(object)

    def _get_reference(self) -> "Reference":
        """
        :return:
            :class:`~git.refs.reference.Reference` object we point to

        :raise TypeError:
            If this symbolic reference is detached, hence it doesn't point to a
            reference, but to a commit.
        """
        sha, target_ref_path = self._get_ref_info(self.repo, self.path)
        if target_ref_path is None:
            raise TypeError(
                "%s is a detached symbolic reference as it points to %r. "
                "Use .commit or .object to access the target directly." % (self, sha)
            )
        return cast("Reference", self.from_path(self.repo, target_ref_path))

    def set_reference(
        self,
        ref: Union[AnyGitObject, "SymbolicReference", str],
        logmsg: Union[str, None] = None,
    ) -> "SymbolicReference":
        """Set this reference without dereferencing it.

        Reference objects create symbolic references; objects and revision strings
        detach it. Git applies its normal reflog policy, even without ``logmsg``.
        """
        self._get_validated_ref_path(self.repo, self.path)
        options = []
        if logmsg is not None:
            if "\0" in logmsg:
                raise ValueError("Reflog messages must not contain NUL")
            first_line = logmsg.split("\n", 1)[0]
            if first_line:
                options = ["-m", first_line]
        if isinstance(ref, SymbolicReference):
            self._get_validated_ref_path(self.repo, ref.path)
            self.repo.git._call_process_safe("symbolic_ref", *options, "--", self.path, ref.path)
        else:
            obj = self._resolve_object(ref)
            if logmsg is not None:
                options.append("--create-reflog")
            self.repo.git._call_process_safe(
                "update_ref",
                "--no-deref",
                *options,
                "--",
                self.path,
                obj.hexsha,
                env=self._reflog_environment(obj) if logmsg is not None else {},
            )
        return self

    @staticmethod
    def _reflog_environment(obj: AnyGitObject) -> Dict[str, Union[str, None]]:
        if obj.type != "commit":
            return {}
        actor = obj.committer
        return {"GIT_COMMITTER_NAME": actor.name, "GIT_COMMITTER_EMAIL": actor.email}

    def _resolve_object(self, ref: Union[AnyGitObject, "SymbolicReference", str]) -> AnyGitObject:
        if isinstance(ref, SymbolicReference):
            obj = ref.object
        elif isinstance(ref, Object):
            obj = ref
        elif isinstance(ref, str):
            Git._check_operand(ref, "revision")
            try:
                obj = self.repo.rev_parse(ref + "^{}")
            except (BadObject, BadName) as exc:
                raise ValueError("Could not extract object from %s" % ref) from exc
        else:
            raise ValueError("Unrecognized value: %r" % ref)
        if self._points_to_commits_only and obj.type != Commit.type:
            raise TypeError("Require commit, got %r" % obj)
        return obj

    @staticmethod
    def _transaction(repo: "Repo", commands: str, logmsg: Union[str, None] = None) -> None:
        # Operands have already passed reference/OID validation. NUL framing keeps
        # reference names separate from the fixed update-ref protocol commands.
        options = []
        if logmsg is not None:
            if "\0" in logmsg:
                raise ValueError("Reflog messages must not contain NUL")
            options.append("--create-reflog")
            first_line = logmsg.split("\n", 1)[0]
            if first_line:
                options.extend(("-m", first_line))
        with tempfile.TemporaryFile() as stream:
            stream.write(commands.encode("utf-8"))
            stream.seek(0)
            repo.git._call_process_safe("update_ref", "--no-deref", "--stdin", "-z", *options, istream=stream)

    # Aliased reference
    @property
    def reference(self) -> "Reference":
        """The reference we point to, available only when not detached.

        Check :attr:`is_detached` before reading this property if a target
        reference is required. To access the target commit or object in either
        state, use :attr:`commit` or :attr:`object` instead.

        Assigning a reference keeps this reference symbolic. Assigning a git
        object or revision string detaches it; reading this property then raises.

        :raise TypeError:
            If this reference is detached when reading the property.
        """
        return self._get_reference()

    @reference.setter
    def reference(self, ref: Union[AnyGitObject, "SymbolicReference", str]) -> "SymbolicReference":
        return self.set_reference(ref)

    ref = reference

    def is_valid(self) -> bool:
        """
        :return:
            ``True`` if the reference is valid, hence it can be read and points to a
            valid object or reference.
        """
        try:
            self.object  # noqa: B018
        except (OSError, ValueError, BadObject, BadName, GitCommandError):
            return False
        else:
            return True

    @property
    def is_detached(self) -> bool:
        """
        :return:
            ``True`` if we are a detached reference, hence we point to a specific commit
            instead to another reference.
        """
        # Inspect only this ref. Constructing its target would recursively inspect
        # symbolic references with nonstandard names through from_path().
        return self._get_ref_info(self.repo, self.path)[1] is None

    def log(self) -> "RefLog":
        """Return Git's commit reflog view, ordered from oldest to newest.

        Non-commit and unavailable objects are omitted by Git. Entries expose the
        new object ID, actor, time and message; raw old object IDs are unavailable.
        """
        return RefLog(self)

    def log_append(
        self,
        oldbinsha: bytes,
        message: Union[str, None],
        newbinsha: Union[bytes, None] = None,
    ) -> "RefLogEntry":
        """Append a reflog entry through Git without changing the reference."""
        return RefLog.append_entry(
            self, oldbinsha, newbinsha if newbinsha is not None else self.commit.binsha, message or ""
        )

    def log_entry(self, index: int) -> "RefLogEntry":
        """Return a Python-indexed entry from Git's commit reflog view."""
        return self.log()[index]

    @classmethod
    def to_full_path(cls, path: Union[PathLike, "SymbolicReference"]) -> PathLike:
        """
        :return:
            String with a full repository-relative path which can be used to initialize
            a :class:`~git.refs.reference.Reference` instance, for instance by using
            :meth:`Reference.from_path <git.refs.reference.Reference.from_path>`.
        """
        if isinstance(path, SymbolicReference):
            path = path.path
        full_ref_path = path
        if not cls._common_path_default:
            return full_ref_path
        if not os.fspath(path).startswith(cls._common_path_default + "/"):
            full_ref_path = "%s/%s" % (cls._common_path_default, path)
        return full_ref_path

    @classmethod
    def delete(cls, repo: "Repo", path: PathLike) -> None:
        """Delete a reference and its reflog without dereferencing symbolic refs."""
        path = cls.to_full_path(path)
        cls._get_validated_ref_path(repo, path)
        repo.git._call_process_safe("update_ref", "--no-deref", "-d", "--", path)
        # END remove reflog

    @classmethod
    def _create(
        cls: Type[T_References],
        repo: "Repo",
        path: PathLike,
        resolve: bool,
        reference: Union["SymbolicReference", str],
        force: bool,
        logmsg: Union[str, None] = None,
    ) -> T_References:
        full_path = cls.to_full_path(path)
        cls._get_validated_ref_path(repo, full_path)
        target = repo.rev_parse(str(reference)) if resolve else reference
        ref = cls(repo, full_path)
        if force:
            ref.set_reference(target, logmsg)
            return ref
        desired: Tuple[Union[str, None], Union[str, None]]
        if isinstance(target, SymbolicReference):
            cls._get_validated_ref_path(repo, target.path)
            desired = (None, os.fspath(target.path))
        else:
            obj = ref._resolve_object(target)
            desired = (obj.hexsha, None)
        try:
            existing = cls._get_ref_info(repo, full_path)
        except ValueError:
            existing = None
        if existing is not None:
            if existing != desired:
                raise OSError("Reference %r already exists with different contents" % full_path)
            return ref
        try:
            if desired[1] is not None:
                cls._transaction(repo, "symref-create %s\0%s\0" % (full_path, desired[1]), logmsg)
            else:
                if logmsg is not None and "\0" in logmsg:
                    raise ValueError("Reflog messages must not contain NUL")
                options = [] if logmsg is None else ["--create-reflog"]
                if logmsg:
                    first_line = logmsg.split("\n", 1)[0]
                    if first_line:
                        options.extend(("-m", first_line))
                repo.git._call_process_safe(
                    "update_ref", "--no-deref", *options, "--", full_path, desired[0], repo._null_hexsha
                )
        except GitCommandError as exc:
            raise OSError("Could not create reference %r" % full_path) from exc
        return ref

    @classmethod
    def create(
        cls: Type[T_References],
        repo: "Repo",
        path: PathLike,
        reference: Union["SymbolicReference", str] = "HEAD",
        logmsg: Union[str, None] = None,
        force: bool = False,
        **kwargs: Any,
    ) -> T_References:
        """Create a new symbolic reference: a reference pointing to another reference.

        :param repo:
            Repository to create the reference in.

        :param path:
            Full path at which the new symbolic reference is supposed to be created at,
            e.g. ``NEW_HEAD`` or ``refs/symrefs/my_new_symref``.

        :param reference:
            The reference which the new symbolic reference should point to.
            If it is a commit-ish, the symbolic ref will be detached.

        :param force:
            If ``True``, force creation even if a symbolic reference with that name
            already exists. Raise :exc:`OSError` otherwise.

        :param logmsg:
            If not ``None``, the message to append to the reflog.
            If ``None``, no reflog entry is written.

        :return:
            Newly created symbolic reference

        :raise OSError:
            If a (Symbolic)Reference with the same name but different contents already
            exists.

        :note:
            This does not alter the current HEAD, index or working tree.
        """
        return cls._create(repo, path, cls._resolve_ref_on_create, reference, force, logmsg)

    def rename(self, new_path: PathLike, force: bool = False) -> "SymbolicReference":
        """Move a reference through an atomic Git reference transaction.

        Branches override this with ``git branch --move``, which also moves reflogs
        and branch configuration. Generic references retain their value only.
        """
        new_path = self.to_full_path(new_path)
        self._get_validated_ref_path(self.repo, self.path)
        self._get_validated_ref_path(self.repo, new_path)
        if self.path == new_path:
            return self
        value = self._get_ref_info(self.repo, self.path)
        try:
            destination = self._get_ref_info(self.repo, new_path)
        except ValueError:
            destination = None
        if destination is not None and not force and value != destination:
            raise OSError("Reference %r already exists" % new_path)
        oid, target = value
        if target is not None:
            command = "symref-create" if destination is None else "symref-update"
            updates = "%s %s\0%s\0symref-delete %s\0%s\0" % (command, new_path, target, self.path, target)
        else:
            command = "create" if destination is None else "update"
            updates = "%s %s\0%s\0" % (command, new_path, oid)
            if command == "update":
                updates += "\0"
            updates += "delete %s\0%s\0" % (self.path, oid)
        self._transaction(self.repo, updates)
        self.path = new_path
        return self

    @classmethod
    def _iter_items(
        cls: Type[T_References], repo: "Repo", common_path: Union[PathLike, None] = None
    ) -> Iterator[T_References]:
        prefix = os.fspath(cls._common_path_default if common_path is None else common_path)
        if prefix:
            cls._check_ref_name_valid(prefix.rstrip("/"))
        options = [] if prefix.startswith("refs/") or prefix == "refs" else ["--include-root-refs"]
        output = repo.git._call_process_safe(
            "for_each_ref", "--format=%(refname)", *options, "--", *([prefix] if prefix else [])
        )
        for path in sorted(output.splitlines()):
            try:
                yield cls.from_path(repo, path)
            except ValueError:
                continue
        # END for each sorted relative refpath

    @classmethod
    def iter_items(
        cls: Type[T_References],
        repo: "Repo",
        common_path: Union[PathLike, None] = None,
        *args: Any,
        **kwargs: Any,
    ) -> Iterator[T_References]:
        """Find all refs in the repository.

        :param repo:
            The :class:`~git.repo.base.Repo`.

        :param common_path:
            Optional keyword argument to the path which is to be shared by all returned
            Ref objects.
            Defaults to class specific portion if ``None``, ensuring that only refs
            suitable for the actual class are returned.

        :return:
            A list of :class:`SymbolicReference`, each guaranteed to be a symbolic ref
            which is not detached and pointing to a valid ref.

            The list is lexicographically sorted. The returned objects are instances of
            concrete subclasses, such as :class:`~git.refs.head.Head` or
            :class:`~git.refs.tag.TagReference`.
        """
        return (r for r in cls._iter_items(repo, common_path) if r.__class__ is SymbolicReference or not r.is_detached)

    @classmethod
    def from_path(cls: Type[T_References], repo: "Repo", path: PathLike) -> T_References:
        """Make a symbolic reference from a path.

        :param path:
            Full ``.git``-directory-relative path name to the Reference to instantiate.

        :note:
            Use :meth:`to_full_path` if you only have a partial path of a known
            Reference type.

        :return:
            Instance of type :class:`~git.refs.reference.Reference`,
            :class:`~git.refs.head.Head`, or :class:`~git.refs.tag.Tag`, depending on
            the given path.
        """
        if not path:
            raise ValueError("Cannot create Reference from %r" % path)

        # Names like HEAD are inserted after the refs module is imported - we have an
        # import dependency cycle and don't want to import these names in-function.
        from . import HEAD, Head, RemoteReference, TagReference, Reference

        for ref_type in (
            HEAD,
            Head,
            RemoteReference,
            TagReference,
            Reference,
            SymbolicReference,
        ):
            try:
                instance = cast(T_References, ref_type(repo, path))
                if instance.__class__ is SymbolicReference and instance.is_detached:
                    raise ValueError("SymbolicRef was detached, we drop it")
                else:
                    return instance

            except ValueError:
                pass
            # END exception handling
        # END for each type to try
        raise ValueError("Could not find reference type suitable to handle path %r" % path)

    def is_remote(self) -> bool:
        """:return: True if this symbolic reference points to a remote branch"""
        return os.fspath(self.path).startswith(self._remote_common_path_default + "/")
