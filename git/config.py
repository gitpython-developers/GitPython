# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Parser for reading and writing configuration files."""

__all__ = ["GitConfigParser", "SectionConstraint"]

from collections import OrderedDict
from collections.abc import MutableMapping
from configparser import (
    DuplicateSectionError,
    Error as ConfigError,
    MissingSectionHeaderError,
    NoOptionError,
    NoSectionError,
    ParsingError,
)
import fnmatch
from functools import wraps
from io import BufferedReader, IOBase
import logging
import os
import os.path as osp
import re
import sys

from git.compat import defenc, force_text
from git.util import LockFile

# typing-------------------------------------------------------

from typing import (
    Any,
    Callable,
    Generic,
    IO,
    Iterator,
    List,
    Dict,
    NoReturn,
    Sequence,
    TYPE_CHECKING,
    Tuple,
    TypeVar,
    Union,
    cast,
)

from git.types import Lit_config_levels, ConfigLevels_Tup, PathLike, assert_never, _T

if TYPE_CHECKING:
    from io import BytesIO

    from git.repo.base import Repo

T_ConfigParser = TypeVar("T_ConfigParser", bound="GitConfigParser")

# -------------------------------------------------------------

_logger = logging.getLogger(__name__)

CONFIG_LEVELS: ConfigLevels_Tup = ("system", "user", "global", "repository")
"""The configuration level of a configuration file."""

CONDITIONAL_INCLUDE_REGEXP = re.compile(
    r'(?<=includeif )"(gitdir|gitdir/i|onbranch|hasconfig:remote\.\*\.url):(.+)"',
    re.IGNORECASE,
)
"""Section pattern to detect conditional includes.

See: https://git-scm.com/docs/git-config#_conditional_includes
"""

UNSAFE_CONFIG_CHARS_RE = re.compile(r"[\r\n\x00]")
"""Characters that cannot be safely written in config names."""

UNSAFE_CONFIG_VALUE_CHARS_RE = re.compile(r"\x00")
"""Characters that cannot be represented in Git config values."""

_MISSING = object()


def _escape_section_subsection(value: str) -> str:
    """Return *value* escaped for Git's double-quoted subsection syntax."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_config_value(value: str) -> str:
    """Return *value* in a canonical representation accepted by Git."""
    escaped = value.replace("\\", "\\\\")
    escaped = escaped.replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\t", "\\t").replace("\b", "\\b")
    return '"%s"' % escaped


class _GitConfigFileParser:
    """Parse Git config syntax using the grammar in Git's ``config.c``.

    The state machine mirrors Git's ``git_parse_source()``, ``get_base_var()``,
    ``get_value()``, and ``parse_value()``. It intentionally deals only with syntax;
    includes are resolved by :class:`GitConfigParser` after each file is parsed.
    """

    def __init__(self, data: str, source: str) -> None:
        self._data = data[1:] if data.startswith("\ufeff") else data
        self._source = source
        self._position = 0
        self._line_number = 1
        self._current_section: Union[str, None] = None

    @staticmethod
    def _is_key_char(char: str) -> bool:
        return char.isascii() and (char.isalnum() or char == "-")

    @staticmethod
    def _is_space(char: str) -> bool:
        return char in " \t\n\v\f\r"

    def _get_char(self) -> Union[str, None]:
        if self._position == len(self._data):
            return None

        char = self._data[self._position]
        self._position += 1
        if char == "\r" and self._position < len(self._data) and self._data[self._position] == "\n":
            self._position += 1
            char = "\n"
        if char == "\n":
            self._line_number += 1
        return char

    def _error(self, line_number: Union[int, None] = None) -> NoReturn:
        number = self._line_number if line_number is None else line_number
        lines = self._data.splitlines()
        line = lines[number - 1] if 0 < number <= len(lines) else ""
        error = ParsingError(self._source)
        error.append(number, repr(line))
        raise error

    def _parse_section(self, line_number: int) -> str:
        base: List[str] = []
        while True:
            char = self._get_char()
            if char is None or char == "\n":
                self._error(line_number)
            if char == "]":
                if not base:
                    self._error(line_number)
                return "".join(base)
            if self._is_space(char):
                break
            if not self._is_key_char(char) and char != ".":
                self._error(line_number)
            base.append(char)

        while char is not None and self._is_space(char) and char != "\n":
            char = self._get_char()
        if char != '"' or not base:
            self._error(line_number)

        subsection: List[str] = []
        while True:
            char = self._get_char()
            if char is None or char == "\n":
                self._error(line_number)
            if char == '"':
                break
            if char == "\\":
                char = self._get_char()
                if char is None or char == "\n":
                    self._error(line_number)
            subsection.append(char)

        if self._get_char() != "]":
            self._error(line_number)
        return '%s "%s"' % ("".join(base), _escape_section_subsection("".join(subsection)))

    def _parse_value(self, line_number: int) -> str:
        value: List[str] = []
        pending_whitespace: List[str] = []
        quoted = False
        comment = False

        while True:
            char = self._get_char()
            if char is None or char == "\n":
                if quoted:
                    self._error(line_number)
                return "".join(value)
            if char == "\x00":
                self._error(line_number)
            if comment:
                continue
            if self._is_space(char) and not quoted:
                if value:
                    pending_whitespace.append(char)
                continue
            if not quoted and char in ";#":
                comment = True
                continue

            if pending_whitespace:
                value.extend(pending_whitespace)
                pending_whitespace = []
            if char == "\\":
                char = self._get_char()
                if char is None:
                    self._error(line_number)
                if char == "\n":
                    continue
                escapes = {"t": "\t", "b": "\b", "n": "\n", "\\": "\\", '"': '"'}
                if char not in escapes:
                    self._error(line_number)
                value.append(escapes[char])
            elif char == '"':
                quoted = not quoted
            else:
                value.append(char)

    def _parse_entry(self, first_char: str, line_number: int) -> Tuple[str, Union[str, None]]:
        option = [first_char]
        char = self._get_char()
        while char is not None and self._is_key_char(char):
            option.append(char)
            char = self._get_char()
        while char in (" ", "\t"):
            char = self._get_char()

        # Git distinguishes a valueless key from a key whose value is "true".
        if char is None or char == "\n":
            return "".join(option), None
        if char != "=":
            self._error(line_number)
        return "".join(option), self._parse_value(line_number)

    def parse(self) -> List[Tuple[str, Union[str, None], Union[str, None]]]:
        events: List[Tuple[str, Union[str, None], Union[str, None]]] = []
        comment = False

        while True:
            line_number = self._line_number
            char = self._get_char()
            if char is None:
                return events
            if char == "\n":
                comment = False
                continue
            if comment:
                continue
            if self._is_space(char):
                continue
            if char in "#;":
                comment = True
                continue
            if char == "[":
                self._current_section = self._parse_section(line_number)
                events.append((self._current_section, None, None))
                continue
            if not (char.isascii() and char.isalpha()):
                self._error(line_number)
            if self._current_section is None:
                line = self._data.splitlines()[line_number - 1]
                raise MissingSectionHeaderError(self._source, line_number, line)
            option, value = self._parse_entry(char, line_number)
            events.append((self._current_section, option, value))


def _canonical_section_name(name: str) -> str:
    """Validate and canonicalize one section name using Git's own grammar."""
    events = _GitConfigFileParser("[%s]" % name, "<section name>").parse()
    sections = [section for section, option, _ in events if option is None]
    if len(sections) != 1:
        raise ValueError("Git config section name does not identify exactly one section")
    return sections[0]


def _section_name_key(name: str) -> str:
    """Return Git's case-insensitive lookup key for a canonical section name."""
    canonical_name = _canonical_section_name(name)
    subsection_start = canonical_name.find(' "')
    if subsection_start == -1:
        return canonical_name.lower()
    return canonical_name[:subsection_start].lower() + canonical_name[subsection_start:]


def needs_values(func: Callable[..., _T]) -> Callable[..., _T]:
    """Return a method for ensuring we read values (on demand) before we try to access
    them."""

    @wraps(func)
    def assure_data_present(self: "GitConfigParser", *args: Any, **kwargs: Any) -> _T:
        self.read()
        return func(self, *args, **kwargs)

    # END wrapper method
    return assure_data_present


def set_dirty_and_flush_changes(non_const_func: Callable[..., _T]) -> Callable[..., _T]:
    """Return a method that checks whether given non constant function may be called.

    If so, the instance will be set dirty. Additionally, we flush the changes right to
    disk.
    """

    def flush_changes(self: "GitConfigParser", *args: Any, **kwargs: Any) -> _T:
        rval = non_const_func(self, *args, **kwargs)
        self._dirty = True
        self.write()
        return rval

    # END wrapper method
    flush_changes.__name__ = non_const_func.__name__
    return flush_changes


class SectionConstraint(Generic[T_ConfigParser]):
    """Constrain a configuration parser to commands for one section.

    It supports all :class:`GitConfigParser` methods that operate on an option.

    :note:
        If used as a context manager, this releases the wrapped parser.
    """

    __slots__ = ("_config", "_section_name")

    _valid_attrs_ = (
        "get_value",
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
        """Return the :class:`GitConfigParser` instance being constrained."""
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


class _GitConfigSectionData:
    """Ordered, multi-valued storage for one Git configuration section."""

    def __init__(self) -> None:
        self._values: "OrderedDict[str, List[Union[str, None]]]" = OrderedDict()

    def __contains__(self, option: str) -> bool:
        return option in self._values

    def __len__(self) -> int:
        return len(self._values)

    def add(self, option: str, value: Union[str, None]) -> None:
        self._values.setdefault(option, []).append(value)

    def set(self, option: str, value: Union[str, None]) -> None:
        self._values[option] = [value]

    def setall(self, option: str, values: List[Union[str, None]]) -> None:
        self._values[option] = list(values)

    def getlast(self, option: str) -> Union[str, None]:
        return self._values[option][-1]

    def getall(self, option: str) -> List[Union[str, None]]:
        return list(self._values[option])

    def remove(self, option: str) -> bool:
        if option not in self._values:
            return False
        del self._values[option]
        return True

    def options(self) -> List[str]:
        return list(self._values)

    def items_all(self) -> List[Tuple[str, List[Union[str, None]]]]:
        return [(option, list(values)) for option, values in self._values.items()]


class _GitConfigSection(MutableMapping):
    """Mapping-style view of one section in a :class:`GitConfigParser`."""

    def __init__(self, parser: "GitConfigParser", name: str) -> None:
        self._parser = parser
        self._name = name

    def __repr__(self) -> str:
        return "<Git config section: %s>" % self._name

    def __getitem__(self, option: str) -> str:
        return self._parser.get(self._name, option)

    def __setitem__(self, option: str, value: Any) -> None:
        self._parser.set(self._name, option, value)

    def __delitem__(self, option: str) -> None:
        if not self._parser.remove_option(self._name, option):
            raise KeyError(option)

    def __iter__(self) -> Iterator[str]:
        return iter(self._parser.options(self._name))

    def __len__(self) -> int:
        return len(self._parser.options(self._name))

    def __contains__(self, option: object) -> bool:
        return isinstance(option, str) and self._parser.has_option(self._name, option)

    def get(self, option: str, fallback: Any = None, **kwargs: Any) -> Any:  # type: ignore[override]
        return self._parser.get(self._name, option, fallback=fallback, **kwargs)

    def getint(self, option: str, fallback: Any = None, **kwargs: Any) -> Any:
        return self._parser.getint(self._name, option, fallback=fallback, **kwargs)

    def getfloat(self, option: str, fallback: Any = None, **kwargs: Any) -> Any:
        return self._parser.getfloat(self._name, option, fallback=fallback, **kwargs)

    def getboolean(self, option: str, fallback: Any = None, **kwargs: Any) -> Any:
        return self._parser.getboolean(self._name, option, fallback=fallback, **kwargs)

    @property
    def parser(self) -> "GitConfigParser":
        return self._parser

    @property
    def name(self) -> str:
        return self._name


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
    """Implements specifics required to read git style configuration files.

    This variation behaves much like the :manpage:`git-config(1)` command, such that the
    configuration will be read on demand based on the filepath given during
    initialization.

    The changes will automatically be written once the instance goes out of scope, but
    can be triggered manually as well.

    The configuration file will be locked if you intend to change values preventing
    other instances to write concurrently.

    :note:
        Section and option names are case-insensitive, while subsection names are
        case-sensitive, matching Git.

    :note:
        If used as a context manager, this will release the locked file.
    """

    # { Configuration
    t_lock = LockFile
    """The lock type determines the type of lock to use in new configuration readers.

    They must be compatible to the :class:`~git.util.LockFile` interface.
    A suitable alternative would be the :class:`~git.util.BlockingLockFile`.
    """

    def __init__(
        self,
        file_or_files: Union[None, PathLike, "BytesIO", Sequence[Union[PathLike, "BytesIO"]]] = None,
        read_only: bool = True,
        merge_includes: bool = True,
        config_level: Union[Lit_config_levels, None] = None,
        repo: Union["Repo", None] = None,
    ) -> None:
        """Initialize a configuration reader to read the given `file_or_files` and to
        possibly allow changes to it by setting `read_only` False.

        :param file_or_files:
            A file path or file object, or a sequence of possibly more than one of them.

        :param read_only:
            If ``True``, the parser may only read the data, but not change it.
            If ``False``, only a single file path or file object may be given. We will
            write back the changes when they happen, or when the parser is
            released. This will not happen if other configuration files have been
            included.

        :param merge_includes:
            If ``True``, we will read files mentioned in ``[include]`` sections and
            merge their contents into ours. This makes it impossible to write back an
            individual configuration file. Thus, if you want to modify a single
            configuration file, turn this off to leave the original dataset unaltered
            when reading it.

        :param repo:
            Reference to repository to use if ``[includeIf]`` sections are found in
            configuration files.
        """
        self._sections: "OrderedDict[str, _GitConfigSectionData]" = OrderedDict()
        # Lookups use case-normalized keys, while canonical rewrites retain the
        # first spelling seen in the file or supplied through the API.
        self._section_name_map: Dict[str, str] = {}
        self._option_name_map: Dict[Tuple[str, str], str] = {}

        if file_or_files is not None:
            self._file_or_files: Union[PathLike, "BytesIO", Sequence[Union[PathLike, "BytesIO"]]] = file_or_files
        else:
            if config_level is None:
                if read_only:
                    self._file_or_files = [
                        get_config_path(cast(Lit_config_levels, f)) for f in CONFIG_LEVELS if f != "repository"
                    ]
                else:
                    raise ValueError("No configuration level or configuration files specified")
            else:
                self._file_or_files = [get_config_path(config_level)]

        self._read_only = read_only
        self._dirty = False
        self._is_initialized = False
        self._merge_includes = merge_includes
        self._repo = repo
        self._lock: Union["LockFile", None] = None
        self._acquire_lock()

    def _acquire_lock(self) -> None:
        if not self._read_only:
            if not self._lock:
                if isinstance(self._file_or_files, (str, os.PathLike)):
                    file_or_files = self._file_or_files
                elif isinstance(self._file_or_files, (tuple, list, Sequence)):
                    raise ValueError(
                        "Writable config parsers can operate on a single file only; multiple files were passed"
                    )
                else:
                    file_or_files = self._file_or_files.name

                # END get filename from handle/stream
                # Initialize lock base - we want to write.
                self._lock = self.t_lock(file_or_files)
            # END lock check

            self._lock._obtain_lock()
        # END read-only check

    def __del__(self) -> None:
        """Write pending changes if required and release locks."""
        # NOTE: Only consistent in Python 2.
        self.release()

    def __enter__(self) -> "GitConfigParser":
        self._acquire_lock()
        return self

    def __exit__(self, *args: Any) -> None:
        self.release()

    def release(self) -> None:
        """Flush changes and release the configuration write lock. This instance must
        not be used anymore afterwards.

        In Python 3, it's required to explicitly release locks and flush changes, as
        ``__del__`` is not called deterministically anymore.
        """
        # Checking for the lock here makes sure we do not raise during write()
        # in case an invalid parser was created who could not get a lock.
        if self.read_only or (self._lock and not self._lock._has_lock()):
            return

        try:
            self.write()
        except IOError:
            _logger.error("Exception during destruction of GitConfigParser", exc_info=True)
        except ReferenceError:
            # This happens in Python 3... and usually means that some state cannot be
            # written as the sections dict cannot be iterated. This usually happens when
            # the interpreter is shutting down. Can it be fixed?
            pass
        finally:
            if self._lock is not None:
                self._lock._release_lock()

    def optionxform(self, optionstr: str) -> str:
        """Normalize option names as Git does; their spelling is case-insensitive."""
        return optionstr.lower()

    @needs_values
    def sections(self) -> List[str]:
        """Return section names with the spelling used in the configuration."""
        return [self._section_name_map.get(section, section) for section in self._sections]

    def __iter__(self) -> Iterator[str]:
        """Iterate over section names with their original spelling."""
        return iter(self.sections())

    def __len__(self) -> int:
        self.read()
        return len(self._sections)

    def __contains__(self, section: object) -> bool:
        return isinstance(section, str) and self.has_section(section)

    @needs_values
    def __getitem__(self, section: str) -> _GitConfigSection:
        """Return a section proxy using Git's section case rules."""
        section_key = self._normalize_section_name(section)
        if section_key not in self._sections:
            raise KeyError(section)
        return _GitConfigSection(self, self._section_name_map.get(section_key, section_key))

    def keys(self) -> List[str]:
        return self.sections()

    def values(self) -> List[_GitConfigSection]:
        return [self[section] for section in self.sections()]

    @staticmethod
    def _normalize_section_name(section: str) -> str:
        return _section_name_key(section)

    @needs_values
    def get(
        self,
        section: str,
        option: str,
        raw: bool = False,
        vars: Union[Dict[str, Any], None] = None,
        fallback: Any = _MISSING,
    ) -> Any:
        """Get an option using Git's section and option case rules."""
        del raw  # Git config values are never interpolated.
        section_key = self._normalize_section_name(section)
        if section_key not in self._sections:
            if fallback is not _MISSING:
                return fallback
            raise NoSectionError(section)

        option_key = self.optionxform(option)
        if vars is not None:
            for var_name, var_value in vars.items():
                if self.optionxform(var_name) == option_key:
                    return var_value
        section_data = self._sections[section_key]
        if option_key not in section_data:
            if fallback is not _MISSING:
                return fallback
            raise NoOptionError(option, self._section_name_map.get(section_key, section))
        value = section_data.getlast(option_key)
        return "true" if value is None else value

    @needs_values
    def has_section(self, section: str) -> bool:
        """Return whether *section* exists, ignoring case in its base name."""
        section = self._normalize_section_name(section)
        return section in self._sections

    @needs_values
    def has_option(self, section: str, option: str) -> bool:
        """Return whether *option* exists using Git's case rules."""
        section = self._normalize_section_name(section)
        return section in self._sections and self.optionxform(option) in self._sections[section]

    @needs_values
    def options(self, section: str) -> List[str]:
        """Return option names with their original spelling."""
        section = self._normalize_section_name(section)
        if section not in self._sections:
            raise NoSectionError(section)
        return [self._option_name_map.get((section, option), option) for option in self._sections[section].options()]

    @needs_values
    @set_dirty_and_flush_changes
    def remove_option(self, section: str, option: str) -> bool:
        """Remove an option using Git's section and option case rules."""
        section = self._normalize_section_name(section)
        option_key = self.optionxform(option)
        if section not in self._sections:
            raise NoSectionError(section)
        removed = self._sections[section].remove(option_key)
        if removed:
            self._option_name_map.pop((section, option_key), None)
        return removed

    @needs_values
    @set_dirty_and_flush_changes
    def remove_section(self, section: str) -> bool:
        """Remove a section while ignoring case in its base name."""
        section = self._normalize_section_name(section)
        removed = section in self._sections
        if removed:
            del self._sections[section]
            self._section_name_map.pop(section, None)
            for name_key in [name_key for name_key in self._option_name_map if name_key[0] == section]:
                del self._option_name_map[name_key]
        return removed

    def _read(self, fp: Union[BufferedReader, IO[bytes]], fpname: str) -> None:
        """Parse one file according to the grammar implemented by Git itself."""
        parser = _GitConfigFileParser(fp.read().decode(defenc), fpname)
        for section, option, value in parser.parse():
            section_key = _section_name_key(section)
            if section_key not in self._sections:
                self._sections[section_key] = _GitConfigSectionData()
                self._section_name_map[section_key] = section
            if option is not None:
                option_key = self.optionxform(option)
                self._sections[section_key].add(option_key, value)
                self._option_name_map.setdefault((section_key, option_key), option)

    def _has_includes(self) -> Union[bool, int]:
        return self._merge_includes and len(self._included_paths())

    def _included_paths(self) -> List[Tuple[str, str]]:
        """List all paths that must be included to configuration.

        :return:
            The list of paths, where each path is a tuple of (option, value).
        """

        def _all_items(section: str) -> List[Tuple[str, str]]:
            """Return all (key, value) pairs for a section, including duplicate keys."""
            section = _section_name_key(section)
            return [
                (key, "true" if value is None else value)
                for key, values in self._sections[section].items_all()
                for value in values
            ]

        paths = []

        for section in self.sections():
            if _section_name_key(section) == "include":
                paths += _all_items(section)

            match = CONDITIONAL_INCLUDE_REGEXP.search(section)
            if match is None or self._repo is None:
                continue

            keyword = match.group(1)
            value = match.group(2).strip()

            if keyword in ["gitdir", "gitdir/i"]:
                value = osp.expanduser(value)

                if not any(value.startswith(s) for s in ["./", "/"]):
                    value = "**/" + value
                if value.endswith("/"):
                    value += "**"

                # Ensure that glob is always case insensitive if required.
                if keyword.endswith("/i"):
                    value = re.sub(
                        r"[a-zA-Z]",
                        lambda m: f"[{m.group().lower()!r}{m.group().upper()!r}]",
                        value,
                    )
                if self._repo.git_dir:
                    if fnmatch.fnmatchcase(os.fspath(self._repo.git_dir), value):
                        paths += _all_items(section)

            elif keyword == "onbranch":
                try:
                    branch_name = self._repo.active_branch.name
                except TypeError:
                    # Ignore section if active branch cannot be retrieved.
                    continue

                if fnmatch.fnmatchcase(branch_name, value):
                    paths += _all_items(section)
            elif keyword == "hasconfig:remote.*.url":
                for remote in self._repo.remotes:
                    if fnmatch.fnmatchcase(remote.url, value):
                        paths += _all_items(section)
                        break
        return paths

    def read(self) -> None:
        """Read the data stored in the files we have been initialized with.

        This will ignore files that cannot be read, possibly leaving an empty
        configuration.

        :raise IOError:
            If a file cannot be handled.
        """
        if self._is_initialized:
            return
        self._is_initialized = True

        files_to_read: List[Union[PathLike, IO]] = [""]
        if isinstance(self._file_or_files, (str, os.PathLike)):
            # For str or Path, as str is a type of Sequence.
            files_to_read = [self._file_or_files]
        elif not isinstance(self._file_or_files, (tuple, list, Sequence)):
            # Could merge with above isinstance once runtime type known.
            files_to_read = [self._file_or_files]
        else:  # For lists or tuples.
            files_to_read = list(self._file_or_files)
        # END ensure we have a copy of the paths to handle

        files_to_read = [osp.abspath(path) if isinstance(path, (str, os.PathLike)) else path for path in files_to_read]

        seen = set(files_to_read)
        num_read_include_files = 0
        while files_to_read:
            file_path = files_to_read.pop(0)
            file_ok = False

            if hasattr(file_path, "seek"):
                # Must be a file-object.
                # TODO: Replace cast with assert to narrow type, once sure.
                file_path = cast(IO[bytes], file_path)
                self._read(file_path, file_path.name)
            else:
                try:
                    with open(file_path, "rb") as fp:
                        file_ok = True
                        self._read(fp, fp.name)
                except IOError:
                    continue

            # Read includes and append those that we didn't handle yet. We expect all
            # paths to be normalized and absolute (and will ensure that is the case).
            if self._has_includes():
                for _, include_path in self._included_paths():
                    if include_path.startswith("~"):
                        include_path = osp.expanduser(include_path)
                    if not osp.isabs(include_path):
                        if not file_ok:
                            continue
                        # END ignore relative paths if we don't know the configuration file path
                        file_path = cast(PathLike, file_path)
                        assert osp.isabs(file_path), "Need absolute paths to be sure our cycle checks will work"
                        include_path = osp.join(osp.dirname(file_path), include_path)
                    # END make include path absolute
                    include_path = osp.normpath(include_path)
                    if include_path in seen or not os.access(include_path, os.R_OK):
                        continue
                    seen.add(include_path)
                    # Insert included file to the top to be considered first.
                    files_to_read.insert(0, include_path)
                    num_read_include_files += 1
                # END each include path in configuration file
            # END handle includes
        # END for each file object to read

        # If there was no file included, we can safely write back (potentially) the
        # configuration file without altering its meaning.
        if num_read_include_files == 0:
            self._merge_includes = False

    def _write(self, fp: IO) -> None:
        """Write a canonical Git-config representation of the configuration state."""

        def write_section(name: str, section_data: _GitConfigSectionData) -> None:
            section_name = self._section_name_map.get(name, name)
            fp.write(("[%s]\n" % _canonical_section_name(section_name)).encode(defenc))

            for key, values in section_data.items_all():
                for raw_value in values:
                    option_name = self._option_name_map.get((name, key), key)
                    if raw_value is None:
                        fp.write(("\t%s\n" % option_name).encode(defenc))
                        continue
                    value = _escape_config_value(self._value_to_string(raw_value))
                    fp.write(("\t%s = %s\n" % (option_name, value)).encode(defenc))

        # END section writing

        for name, section_data in self._sections.items():
            write_section(name, section_data)

    @needs_values
    def items(self, section_name: str) -> List[Tuple[str, str]]:
        """:return: list((option, value), ...) pairs of all items in the given section"""
        section_name = self._normalize_section_name(section_name)
        if section_name not in self._sections:
            raise NoSectionError(section_name)
        return [
            (self._option_name_map.get((section_name, key), key), "true" if values[-1] is None else values[-1])
            for key, values in self._sections[section_name].items_all()
        ]

    @needs_values
    def items_all(self, section_name: str) -> List[Tuple[str, List[str]]]:
        """:return: list((option, [values...]), ...) pairs of all items in the given section"""
        section_name = self._normalize_section_name(section_name)
        if section_name not in self._sections:
            raise NoSectionError(section_name)
        return [
            (
                self._option_name_map.get((section_name, key), key),
                ["true" if value is None else value for value in values],
            )
            for key, values in self._sections[section_name].items_all()
        ]

    @needs_values
    def write(self) -> None:
        """Write changes to our file, if there are changes at all.

        :raise IOError:
            If this is a read-only writer instance or if we could not obtain a file
            lock.
        """
        self._assure_writable("write")
        if not self._dirty:
            return

        if isinstance(self._file_or_files, (list, tuple)):
            raise AssertionError(
                "Cannot write back if there is not exactly a single file to write to, have %i files"
                % len(self._file_or_files)
            )
        # END assert multiple files

        if self._has_includes():
            _logger.debug(
                "Skipping write-back of configuration file as include files were merged in."
                + "Set merge_includes=False to prevent this."
            )
            return
        # END stop if we have include files

        fp = self._file_or_files

        # We have a physical file on disk, so get a lock.
        is_file_lock = isinstance(fp, (str, os.PathLike, IOBase))  # TODO: Use PathLike (having dropped 3.5).
        if is_file_lock and self._lock is not None:  # Else raise error?
            self._lock._obtain_lock()

        if not hasattr(fp, "seek"):
            fp = cast(PathLike, fp)
            with open(fp, "wb") as fp_open:
                self._write(fp_open)
        else:
            fp = cast("BytesIO", fp)
            fp.seek(0)
            # Make sure we do not overwrite into an existing file.
            if hasattr(fp, "truncate"):
                fp.truncate()
            self._write(fp)

    def _assure_writable(self, method_name: str) -> None:
        if self.read_only:
            raise IOError("Cannot execute non-constant method %s.%s" % (self, method_name))

    def _add_section(self, section: str) -> None:
        section_name = _canonical_section_name(section)
        section_key = _section_name_key(section_name)
        if section_key in self._sections:
            raise DuplicateSectionError(section_name)
        self._sections[section_key] = _GitConfigSectionData()
        self._section_name_map[section_key] = section_name

    @needs_values
    @set_dirty_and_flush_changes
    def add_section(self, section: str) -> None:
        """Assures added options will stay in order."""
        self._assure_config_name_safe(section, "section")
        self._add_section(section)

    @property
    def read_only(self) -> bool:
        """:return: ``True`` if this instance may change the configuration file"""
        return self._read_only

    # FIXME: Figure out if default or return type can really include bool.
    def get_value(
        self,
        section: str,
        option: str,
        default: Union[int, float, str, bool, None] = None,
    ) -> Union[int, float, str, bool]:
        """Get an option's value.

        If multiple values are specified for this option in the section, the last one
        specified is returned.

        :param default:
            If not ``None``, the given default value will be returned in case the option
            did not exist.

        :return:
            A properly typed value, either int, float or string

        :raise TypeError:
            In case the value could not be understood.
            Otherwise the parser's lookup exceptions will be raised.
        """
        try:
            valuestr = self.get(section, option)
        except Exception:
            if default is not None:
                return default
            raise

        return self._string_to_value(valuestr)

    def get_values(
        self,
        section: str,
        option: str,
        default: Union[int, float, str, bool, None] = None,
    ) -> List[Union[int, float, str, bool]]:
        """Get an option's values.

        If multiple values are specified for this option in the section, all are
        returned.

        :param default:
            If not ``None``, a list containing the given default value will be returned
            in case the option did not exist.

        :return:
            A list of properly typed values, either int, float or string

        :raise TypeError:
            In case the value could not be understood.
            Otherwise the parser's lookup exceptions will be raised.
        """
        try:
            self.sections()
            section = self._normalize_section_name(section)
            lst = self._sections[section].getall(self.optionxform(option))
        except Exception:
            if default is not None:
                return [default]
            raise

        return [True if valuestr is None else self._string_to_value(valuestr) for valuestr in lst]

    def _get_with_fallback(self, section: str, option: str, fallback: Any) -> Any:
        if fallback is _MISSING:
            return self.get(section, option)
        return self.get(section, option, fallback=fallback)

    def getint(self, section: str, option: str, fallback: Any = _MISSING, **kwargs: Any) -> Any:
        """Return an integer parsed with Git's base prefixes and binary suffixes."""
        del kwargs
        value = self._get_with_fallback(section, option, fallback)
        if value is fallback and fallback is not _MISSING:
            return fallback
        match = re.fullmatch(r"([+-]?)(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)([kKmMgG]?)", value)
        if match is None:
            raise ValueError("Not a valid Git integer: %r" % value)
        sign, number, suffix = match.groups()
        if number.lower().startswith("0x"):
            base = 16
        elif len(number) > 1 and number.startswith("0"):
            base = 8
        else:
            base = 10
        factor = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[suffix.lower()]
        parsed = int(number, base) * factor
        return -parsed if sign == "-" else parsed

    def getfloat(self, section: str, option: str, fallback: Any = _MISSING, **kwargs: Any) -> Any:
        """Return a floating-point value parsed with Git's binary suffixes."""
        del kwargs
        value = self._get_with_fallback(section, option, fallback)
        if value is fallback and fallback is not _MISSING:
            return fallback
        match = re.fullmatch(
            r"([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)([kKmMgG]?)",
            value,
        )
        if match is None:
            raise ValueError("Not a valid Git floating-point value: %r" % value)
        number, suffix = match.groups()
        factor = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[suffix.lower()]
        return float(number) * factor

    def getboolean(self, section: str, option: str, fallback: Any = _MISSING, **kwargs: Any) -> Any:
        """Return a boolean using Git's spelling and numeric rules."""
        del kwargs
        value = self._get_with_fallback(section, option, fallback)
        if value is fallback and fallback is not _MISSING:
            return fallback
        normalized = value.lower()
        if normalized in ("true", "yes", "on"):
            return True
        if normalized in ("", "false", "no", "off"):
            return False
        try:
            return self.getint(section, option) != 0
        except ValueError as error:
            raise ValueError("Not a boolean: %r" % value) from error

    def _string_to_value(self, valuestr: str) -> Union[int, float, str, bool]:
        types = (int, float)
        for numtype in types:
            try:
                val = numtype(valuestr)
                # truncated value ?
                if val != float(valuestr):
                    continue
                return val
            except (ValueError, TypeError):
                continue
        # END for each numeric type

        # Try boolean values as git uses them.
        vl = valuestr.lower()
        if vl == "false":
            return False
        if vl == "true":
            return True

        if not isinstance(valuestr, str):
            raise TypeError(
                "Invalid value type: only int, long, float and str are allowed",
                valuestr,
            )

        return valuestr

    def _value_to_string(self, value: Union[str, bytes, int, float, bool]) -> str:
        if isinstance(value, (int, float, bool)):
            return str(value)
        return force_text(value)

    def _value_to_string_safe(self, value: Union[str, bytes, int, float, bool]) -> str:
        value_str = self._value_to_string(value)
        if UNSAFE_CONFIG_VALUE_CHARS_RE.search(value_str):
            raise ValueError("Git config values must not contain NUL")
        return value_str

    def _assure_config_name_safe(self, name: str, label: str) -> None:
        if not isinstance(name, str):
            raise TypeError("Git config %s names must be strings" % label)
        if UNSAFE_CONFIG_CHARS_RE.search(name):
            raise ValueError("Git config %s names must not contain CR, LF, or NUL" % label)
        if label == "section":
            try:
                _canonical_section_name(name)
            except ConfigError as error:
                raise ValueError("Invalid Git config section name: %s" % name) from error
        elif label == "option":
            if not name or not (name[0].isascii() and name[0].isalpha()):
                raise ValueError("Git config option names must start with an ASCII letter")
            if not all(_GitConfigFileParser._is_key_char(char) for char in name):
                raise ValueError("Git config option names may contain only ASCII letters, digits, and hyphens")

    @needs_values
    @set_dirty_and_flush_changes
    def set(
        self,
        section: str,
        option: str,
        value: Union[str, bytes, int, float, bool, None] = None,
    ) -> None:
        self._assure_config_name_safe(section, "section")
        self._assure_config_name_safe(option, "option")
        section = self._normalize_section_name(section)
        option_key = self.optionxform(option)
        if value is not None:
            value = self._value_to_string_safe(value)
        if section not in self._sections:
            raise NoSectionError(section)
        self._sections[section].set(option_key, value)
        self._option_name_map.setdefault((section, option_key), option)

    @needs_values
    @set_dirty_and_flush_changes
    def set_value(self, section: str, option: str, value: Union[str, bytes, int, float, bool]) -> "GitConfigParser":
        """Set the given option in section to the given value.

        This will create the section if required, and will not throw as opposed to the
        lower-level :meth:`set` method.

        :param section:
            Name of the section in which the option resides or should reside.

        :param option:
            Name of the options whose value to set.

        :param value:
            Value to set the option to. It must be a string or convertible to a string.

        :return:
            This instance
        """
        self._assure_config_name_safe(section, "section")
        self._assure_config_name_safe(option, "option")
        section_name = _canonical_section_name(section)
        section = self._normalize_section_name(section)
        option_key = self.optionxform(option)
        value_str = self._value_to_string_safe(value)
        if not self.has_section(section):
            self._add_section(section_name)
        self._sections[section].set(option_key, value_str)
        self._option_name_map.setdefault((section, option_key), option)
        return self

    @needs_values
    @set_dirty_and_flush_changes
    def add_value(self, section: str, option: str, value: Union[str, bytes, int, float, bool]) -> "GitConfigParser":
        """Add a value for the given option in section.

        This will create the section if required, and will not throw as opposed to the
        lower-level :meth:`set` method. The value becomes the new value of the
        option as returned by :meth:`get_value`, and appends to the list of values
        returned by :meth:`get_values`.

        :param section:
            Name of the section in which the option resides or should reside.

        :param option:
            Name of the option.

        :param value:
            Value to add to option. It must be a string or convertible to a string.

        :return:
            This instance
        """
        self._assure_config_name_safe(section, "section")
        self._assure_config_name_safe(option, "option")
        section_name = _canonical_section_name(section)
        section = self._normalize_section_name(section)
        option_name = option
        option = self.optionxform(option_name)
        value_str = self._value_to_string_safe(value)
        if not self.has_section(section):
            self.add_section(section_name)
        self._sections[section].add(option, value_str)
        self._option_name_map.setdefault((section, option), option_name)
        return self

    def rename_section(self, section: str, new_name: str) -> "GitConfigParser":
        """Rename the given section to `new_name`.

        :raise ValueError:
            If:

            * `section` doesn't exist.
            * A section with `new_name` does already exist.

        :return:
            This instance
        """
        section = self._normalize_section_name(section)
        self._assure_config_name_safe(new_name, "section")
        new_section_name = _canonical_section_name(new_name)
        new_name = self._normalize_section_name(new_section_name)
        if not self.has_section(section):
            raise ValueError("Source section '%s' doesn't exist" % section)
        if self.has_section(new_name):
            raise ValueError("Destination section '%s' already exists" % new_name)

        self._sections[new_name] = _GitConfigSectionData()
        self._section_name_map[new_name] = new_section_name
        new_section = self._sections[new_name]
        for option_key, values in self._sections[section].items_all():
            new_section.setall(option_key, values)
            self._option_name_map[(new_name, option_key)] = self._option_name_map.get((section, option_key), option_key)
        # END for each value to copy

        # This call writes back the changes, which is why we don't have the respective
        # decorator.
        self.remove_section(section)
        return self
