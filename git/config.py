# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Git configuration access through ``git config``."""

__all__ = ["GitConfigParser", "SectionConstraint"]

import configparser as cp
import os
import os.path as osp
import re
import sys
import tempfile
from contextlib import contextmanager
from typing import Any, Dict, Generic, Iterator, List, OrderedDict, Sequence, Tuple, TypeVar, Union, TYPE_CHECKING

from git.compat import defenc, force_text
from git.exc import GitCommandError
from git.types import _T, ConfigLevels_Tup, Lit_config_levels, PathLike, assert_never

if TYPE_CHECKING:
    from io import BytesIO
    from git.repo.base import Repo

T_ConfigParser = TypeVar("T_ConfigParser", bound="GitConfigParser")
T_OMD_value = TypeVar("T_OMD_value", str, bytes, int, float, bool, None)
OrderedDict_OMD = OrderedDict[str, List[T_OMD_value]]
CONFIG_LEVELS: ConfigLevels_Tup = ("system", "user", "global", "repository")


class SectionConstraint(Generic[T_ConfigParser]):
    """Constrains a ConfigParser to only option commands which are constrained to
    always use the section we have been initialized with.

    It supports all ConfigParser methods that operate on an option.

    :note:
        If used as a context manager, will release the wrapped ConfigParser.
    """

    __slots__ = ("_config", "_section_name")

    _valid_attrs_ = (
        "get_value",
        "get_values",
        "add_value",
        "items",
        "items_all",
        "set_value",
        "get",
        "set",
        "getint",
        "getfloat",
        "getboolean",
        "has_option",
        "remove_section",
        "remove_option",
        "options",
    )

    def __init__(self, config: T_ConfigParser, section: str) -> None:
        self._config = config
        self._section_name = section

    def __del__(self) -> None:
        # Yes, for some reason, we have to call it explicitly for it to work in PY3 !
        # Apparently __del__ doesn't get call anymore if refcount becomes 0
        # Ridiculous ... .
        self._config.release()

    def __getattr__(self, attr: str) -> Any:
        if attr in self._valid_attrs_:
            return lambda *args, **kwargs: self._call_config(attr, *args, **kwargs)
        return super().__getattribute__(attr)

    def _call_config(self, method: str, *args: Any, **kwargs: Any) -> Any:
        """Call the configuration at the given method which must take a section name as
        first argument."""
        return getattr(self._config, method)(self._section_name, *args, **kwargs)

    @property
    def config(self) -> T_ConfigParser:
        """return: ConfigParser instance we constrain"""
        return self._config

    def release(self) -> None:
        """Equivalent to :meth:`GitConfigParser.release`, which is called on our
        underlying parser instance."""
        return self._config.release()

    def __enter__(self) -> "SectionConstraint[T_ConfigParser]":
        self._config.__enter__()
        return self

    def __exit__(self, exception_type: str, exception_value: str, traceback: str) -> None:
        self._config.__exit__(exception_type, exception_value, traceback)


def _normalize_name(name: str) -> str:
    """Fold section and option names, leaving quoted subsections unchanged."""
    prefix, separator, subsection = name.partition('"')
    return prefix.lower() + separator + subsection


class _OMD(OrderedDict_OMD):
    """Ordered multi-dict matching config names while retaining their first spelling."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._keymap: Dict[str, str] = {}
        super().__init__(*args, **kwargs)

    def _key(self, key: str) -> str:
        stored = self._keymap.get(_normalize_name(key), key)
        return stored if super().__contains__(stored) else key

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and super().__contains__(self._key(key))

    def __delitem__(self, key: str) -> None:
        super().__delitem__(self._key(key))
        del self._keymap[_normalize_name(key)]

    def __setitem__(self, key: str, value: _T) -> None:
        self.setall(key, [value])

    def clear(self) -> None:
        super().clear()
        self._keymap.clear()

    def add(self, key: str, value: Any) -> None:
        if key not in self:
            self[key] = value
            return

        self.getall(key).append(value)

    def setall(self, key: str, values: List[_T]) -> None:
        key = self._key(key)
        super().__setitem__(key, values)
        self._keymap[_normalize_name(key)] = key

    def __getitem__(self, key: str) -> Any:
        return super().__getitem__(self._key(key))[-1]

    def getlast(self, key: str) -> Any:
        return self[key]

    def setlast(self, key: str, value: Any) -> None:
        if key not in self:
            self[key] = value
            return

        self.getall(key)[-1] = value

    def get(self, key: str, default: Union[_T, None] = None) -> Union[_T, None]:  # type: ignore[override]
        return super().get(self._key(key), [default])[-1]

    def getall(self, key: str) -> List[_T]:
        return super().__getitem__(self._key(key))

    def items(self) -> List[Tuple[str, _T]]:  # type: ignore[override]
        """List of (key, last value for key)."""
        return [(k, self[k]) for k in self]

    def items_all(self) -> List[Tuple[str, List[_T]]]:
        """List of (key, list of values for key)."""
        return [(k, self.getall(k)) for k in self]


def get_config_path(config_level: Lit_config_levels) -> str:
    # We do not support an absolute path of the gitconfig on Windows.
    # Use the global config instead.
    if sys.platform == "win32" and config_level == "system":
        config_level = "global"

    if config_level == "system":
        return "/etc/gitconfig"
    elif config_level == "user":
        config_home = os.environ.get("XDG_CONFIG_HOME") or osp.join(os.environ.get("HOME", "~"), ".config")
        return osp.normpath(osp.expanduser(osp.join(config_home, "git", "config")))
    elif config_level == "global":
        return osp.normpath(osp.expanduser("~/.gitconfig"))
    elif config_level == "repository":
        raise ValueError("No repo to get repository configuration from. Use Repo._get_config_path")
    else:
        # Should not reach here. Will raise ValueError if does. Static typing will warn
        # about missing elifs.
        assert_never(  # type: ignore[unreachable]
            config_level,
            ValueError(f"Invalid configuration level: {config_level!r}"),
        )


class GitConfigParser:
    """Read and modify Git configuration using Git's parser and file locking.

    File paths, byte streams, and lists of sources are accepted for reading. Writers
    operate on one source, updating it immediately. Git locks each mutation; a writer
    does not reserve a lifetime lock. Git canonicalizes enumerated section/option
    names, while preserving subsection case and duplicate values.

    Empty sections, raw configuration parsing/serialization, and writing valueless
    options are not supported. Existing valueless options remain readable.
    """

    BOOLEAN_STATES = cp.RawConfigParser.BOOLEAN_STATES

    def __init__(
        self,
        file_or_files: Union[None, PathLike, "BytesIO", Sequence[Union[PathLike, "BytesIO"]]] = None,
        read_only: bool = True,
        merge_includes: bool = True,
        config_level: Union[Lit_config_levels, None] = None,
        repo: Union["Repo", None] = None,
    ) -> None:
        if file_or_files is None:
            if config_level is not None:
                file_or_files = get_config_path(config_level)
            elif read_only:
                file_or_files = [get_config_path(level) for level in CONFIG_LEVELS if level != "repository"]
            else:
                raise ValueError("No configuration level or configuration files specified")
        if isinstance(file_or_files, Sequence) and not isinstance(file_or_files, (str, os.PathLike)):
            file_or_files = list(file_or_files)
        if not read_only and isinstance(file_or_files, (list, tuple)):
            raise ValueError("Configuration writers require a single file or stream")
        self._file_or_files = file_or_files
        self._read_only = read_only
        self._merge_includes = merge_includes
        self._repo = repo
        self._is_initialized = False
        self._sections = _OMD()

    @property
    def read_only(self) -> bool:
        return self._read_only

    def __enter__(self) -> "GitConfigParser":
        return self

    def __exit__(self, *args: Any) -> None:
        self.release()

    def release(self) -> None:
        """Changes are already flushed by each mutation."""

    def write(self) -> None:
        """Flush hook for subclasses; Git has already written each change."""
        self._assure_writable("write")

    def _assure_writable(self, method: str) -> None:
        if self.read_only:
            raise OSError("Cannot modify a read-only configuration: %s" % method)

    @contextmanager
    def _source(self, source: Any, writing: bool = False) -> Iterator[str]:
        if isinstance(source, (str, os.PathLike)):
            path = osp.abspath(source)
            if "\0" in path:
                raise ValueError("Configuration paths must not contain NUL")
            yield path
            return
        # Streams carry bytes only; Git owns parsing and serialization.
        position = source.tell()
        source.seek(0)
        data = source.read()
        source.seek(position)
        if not isinstance(data, bytes):
            raise TypeError("Configuration streams must contain bytes")
        with tempfile.TemporaryDirectory(prefix="gitpython-config-") as directory:
            path = osp.join(directory, "config")
            with open(path, "wb") as stream:
                stream.write(data)
            yield path
            if writing:
                with open(path, "rb") as stream:
                    data = stream.read()
                source.seek(0)
                source.write(data)
                source.truncate()
                source.seek(0)

    def _git(self) -> Any:
        from git.cmd import Git

        if self._repo is not None:
            command = getattr(self._repo, "git", None)
            if command is not None:
                return command
            return Git(self._repo.working_dir)
        return Git()

    def _call_config(self, filename: str, *args: str, **kwargs: Any) -> Any:
        try:
            return self._git()._call_process_safe("config", *args, **kwargs)
        except GitCommandError as error:
            # git-config documents statuses 3 and 4 for malformed/unwritable
            # files. Reads use the generic fatal status, so recognize only its
            # explicit config diagnostics in the fixed C locale.
            if error.status == 3 or (error.status == 128 and "fatal: bad config line " in error.stderr):
                raise cp.ParsingError(filename) from error
            if (
                error.status == 4
                or (error.status == 255 and "could not lock config file " in error.stderr)
                or (
                    error.status == 128
                    and any(message in error.stderr for message in ("unable to read config file", "unable to access"))
                )
            ):
                raise OSError(error.stderr) from error
            raise

    @staticmethod
    def _section_name(section: str) -> str:
        """Convert the public ``section "subsection"`` spelling to a Git key prefix."""
        if not isinstance(section, str) or any(c in section for c in "\0\r\n"):
            raise ValueError("Invalid configuration section name")
        match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9.-]*)(?:[ \t]+"((?:[^"\\]|\\.)*)")?', section)
        if match is None:
            raise ValueError("Invalid configuration section name: %r" % section)
        base, subsection = match.groups()
        if subsection is None:
            return base.lower()
        subsection = re.sub(r"\\(.)", r"\1", subsection)
        return base.lower() + "." + subsection

    @classmethod
    def _key(cls, section: str, option: str) -> str:
        if not isinstance(option, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", option):
            raise ValueError("Invalid Git configuration option name: %r" % option)
        return cls._section_name(section) + "." + option.lower()

    @staticmethod
    def _public_section(prefix: str) -> str:
        section, separator, subsection = prefix.partition(".")
        if not separator:
            return section
        return section + ' "' + subsection.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def read(self) -> None:
        """Load values from Git's NUL-delimited output, including Git-resolved includes."""
        if self._is_initialized:
            return
        sources: Any = self._file_or_files
        if not isinstance(sources, (list, tuple)):
            sources = [sources]
        sections = _OMD()
        for source in sources:
            if isinstance(source, (str, os.PathLike)) and not osp.exists(source):
                continue
            with self._source(source) as filename:
                args = (
                    "list",
                    "--null",
                    "--file",
                    filename if isinstance(source, (str, os.PathLike)) else "-",
                    "--includes" if self._merge_includes else "--no-includes",
                )
                if isinstance(source, (str, os.PathLike)):
                    data = self._call_config(filename, *args, stdout_as_string=False)
                else:
                    with open(filename, "rb") as stream:
                        data = self._call_config("<stream>", *args, istream=stream, stdout_as_string=False)
            for record in data.split(b"\0"):
                if not record:
                    continue
                key, separator, value = record.partition(b"\n")
                prefix, option = key.decode(defenc).rsplit(".", 1)
                section = self._public_section(prefix)
                if section not in sections:
                    sections[section] = _OMD()
                sections[section].add(option, value.decode(defenc) if separator else None)
        self._sections = sections
        self._is_initialized = True

    def sections(self) -> List[str]:
        self.read()
        return list(self._sections)

    def has_section(self, section: str) -> bool:
        self.read()
        return self._public_section(self._section_name(section)) in self._sections

    def _section(self, section: str) -> Any:
        self.read()
        name = self._public_section(self._section_name(section))
        if name not in self._sections:
            raise cp.NoSectionError(section)
        return self._sections[name]

    def options(self, section: str) -> List[str]:
        return list(self._section(section))

    def has_option(self, section: str, option: str) -> bool:
        return self.has_section(section) and option in self._section(section)

    def get(self, section: str, option: str, *, raw: bool = False, vars: Any = None, **kwargs: Any) -> Any:
        try:
            values = self._section(section)
            if option not in values:
                raise cp.NoOptionError(option, section)
            return values[option]
        except (cp.NoSectionError, cp.NoOptionError):
            if "fallback" in kwargs:
                return kwargs["fallback"]
            raise

    def getint(self, section: str, option: str) -> int:
        return int(self.get(section, option))

    def getfloat(self, section: str, option: str) -> float:
        return float(self.get(section, option))

    def getboolean(self, section: str, option: str) -> bool:
        value = self.get(section, option)
        if value is None:
            return True
        if value == "":
            return False
        try:
            return self.BOOLEAN_STATES[value.lower()]
        except KeyError:
            raise ValueError("Not a boolean: %s" % value) from None

    def items(self, section: str) -> List[Tuple[str, Any]]:
        return self._section(section).items()

    def items_all(self, section: str) -> List[Tuple[str, List[Any]]]:
        return self._section(section).items_all()

    @staticmethod
    def _string_to_value(value: Any) -> Any:
        if value is None:
            return ""
        for conversion in (int, float):
            try:
                converted = conversion(value)
                if converted == float(value):
                    return converted
            except (TypeError, ValueError):
                pass
        if value.lower() in ("false", "no", "off"):
            return False
        if value.lower() in ("true", "yes", "on"):
            return True
        return value

    def get_value(self, section: str, option: str, default: Any = None) -> Any:
        try:
            return self._string_to_value(self.get(section, option))
        except (cp.NoSectionError, cp.NoOptionError):
            if default is not None:
                return default
            raise

    def get_values(self, section: str, option: str, default: Any = None) -> List[Any]:
        try:
            self.get(section, option)
            return [self._string_to_value(value) for value in self._section(section).getall(option)]
        except (cp.NoSectionError, cp.NoOptionError):
            if default is not None:
                return [default]
            raise

    def _mutate(self, operation: str, *args: str) -> None:
        self._assure_writable(operation)
        with self._source(self._file_or_files, writing=True) as filename:
            self._call_config(filename, operation, "--file", filename, *args)
        self._is_initialized = False
        self.write()

    @staticmethod
    def _value(value: Any) -> str:
        if value is None:
            raise ValueError("Writing valueless Git configuration options is unsupported")
        value = str(value) if isinstance(value, (int, float, bool)) else force_text(value)
        if any(c in value for c in "\0\r"):
            raise ValueError("Git configuration values must not contain CR or NUL")
        return value

    def set(self, section: str, option: str, value: Any = None) -> None:
        self._assure_writable("set")
        if not self.has_section(section):
            raise cp.NoSectionError(section)
        self.set_value(section, option, value)

    def set_value(self, section: str, option: str, value: Any) -> "GitConfigParser":
        key = self._key(section, option)
        self._mutate("set", "--all", "--", key, self._value(value))
        return self

    def add_value(self, section: str, option: str, value: Any) -> "GitConfigParser":
        key = self._key(section, option)
        self._mutate("set", "--append", "--", key, self._value(value))
        return self

    def remove_option(self, section: str, option: str) -> bool:
        self._assure_writable("remove_option")
        if not self.has_option(section, option):
            return False
        self._mutate("unset", "--all", "--", self._key(section, option))
        return True

    def remove_section(self, section: str) -> bool:
        self._assure_writable("remove_section")
        if not self.has_section(section):
            return False
        self._mutate("remove-section", "--", self._section_name(section))
        return True

    def rename_section(self, section: str, new_name: str) -> "GitConfigParser":
        self._assure_writable("rename_section")
        if not self.has_section(section):
            raise ValueError("Source section %r does not exist" % section)
        if self.has_section(new_name):
            raise ValueError("Destination section %r already exists" % new_name)
        self._mutate("rename-section", "--", self._section_name(section), self._section_name(new_name))
        return self
