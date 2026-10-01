"""The configuration facade follows Git's parser and mutation semantics."""

import configparser
from collections import UserList
from io import BytesIO
import os
import time
from unittest import mock

import pytest

from git import Git, GitCommandError, GitConfigParser, Repo
from git.config import SectionConstraint
from test.lib import fixture_path
from test.lib.fixtures import read_only_fixture, writable_fixture


@pytest.fixture
def config_directory(request):
    scenario = "values" if request.node.originalname == "test_config_values_and_mutations" else "empty"
    with writable_fixture("config.sh", scenario) as fixture:
        yield fixture.path()


@pytest.mark.parametrize(
    "text, expected",
    [
        ("9007199254740993", 9007199254740993),
        ("9223372036854775807", 9223372036854775807),
        ("-9007199254740993", -9007199254740993),
        ("11.11", 11.11),
        ("1e3", 1000.0),
        ("nan", "nan"),
        ("NaN", "NaN"),
        ("true", True),
        ("false", False),
    ],
)
def test_numeric_config_conversion_preserves_precision_and_types(text, expected):
    with GitConfigParser(BytesIO(("[values]\nnumber = %s\n" % text).encode("ascii"))) as config:
        value = config.get_value("values", "number")
        assert value == expected
        assert type(value) is type(expected)
        assert config.get_values("values", "number") == [expected]


@pytest.mark.parametrize("stream", [False, True])
def test_config_values_and_mutations(config_directory, stream):
    path = config_directory / "config"
    content = path.read_bytes()
    source = BytesIO(content) if stream else path
    with GitConfigParser(source, read_only=False) as config:
        assert config.sections() == ["core", 'remote "Origin"']
        assert config.get_values("CORE", "NUMBER") == [1, 2]
        assert config.getboolean("core", "flag") is True
        assert config.get_value("core", "flag") == ""
        config.set_value("core", "number", 3)
        config.add_value("core", "number", 4)
        assert config.items_all("core") == [("flag", [None]), ("number", ["3", "4"])]
        config.set_value("core", "empty", "")
        assert config.getboolean("core", "empty") is False
        config.rename_section('remote "Origin"', 'remote "Other"')
        assert config.get('REMOTE "Other"', "URL") == "first"
        assert config.remove_option("core", "empty")
        assert not config.remove_option("core", "empty")
        assert config.remove_section('remote "Other"')
        config.write()
    assert GitConfigParser(source).get_values("core", "number") == [3, 4]
    assert (source.getvalue() if stream else path.read_bytes()).startswith(b"[CoRe]\nFlag\n")


def test_config_includes_and_repository_conditions():
    path = read_only_fixture("config.sh", "includes")
    with Repo(path / "repo") as repo:
        assert GitConfigParser(path / "config", repo=repo).get_values("values", "source") == [
            "before",
            "after",
            "included",
            "included",
        ]
        assert GitConfigParser(path / "config", merge_includes=False).get_values("values", "source") == [
            "before",
            "after",
        ]


def test_config_multiple_files_and_missing_values():
    tmp_path = read_only_fixture("config.sh", "multiple")
    one, two = tmp_path / "one", tmp_path / "two"
    reader = GitConfigParser(UserList([one, tmp_path / "absent", two]))
    assert reader.get_values("values", "number") == [1, 2]
    assert reader.getint("values", "number") == 2
    assert reader.get_value("absent", "key", 5) == 5
    assert reader.get("values", "absent", fallback="default") == "default"
    with pytest.raises(configparser.NoSectionError):
        reader.get("absent", "key")
    with pytest.raises(configparser.NoOptionError):
        reader.get("values", "absent")
    with pytest.raises(OSError):
        reader.set_value("values", "number", 3)
    with pytest.raises(ValueError):
        GitConfigParser([one, two], read_only=False)


@pytest.mark.parametrize(
    "value", ["--file=outside", ' first # ; " \\ last ', "line one\nline two", "tabs\tand\bbackspace"]
)
def test_config_values_are_literals(config_directory, value):
    path = config_directory / "config"
    with GitConfigParser(path, read_only=False) as config:
        config.set_value('remote "strange.name"', "url", value)
        assert config.get('remote "strange.name"', "url") == value
    assert Git().config("get", "--file", str(path), "remote.strange.name.url") == value.rstrip("\n")


@pytest.mark.parametrize(
    "section, option, value",
    [
        ("--file=outside", "name", "value"),
        ("user\n[other]", "name", "value"),
        ("user", "--file", "value"),
        ("user", "name\nother", "value"),
        ("user", "name", "value\0other"),
        ("user", "name", "value\rother"),
        ("user", "name", None),
    ],
)
def test_config_rejects_invalid_fields_before_git(config_directory, section, option, value):
    config = GitConfigParser(config_directory / "config", read_only=False)
    with mock.patch.object(Git, "_call_process_safe", side_effect=AssertionError("Git must not run")):
        with pytest.raises(ValueError):
            config.set_value(section, option, value)


def test_config_writers_use_git_locking(config_directory):
    path = config_directory / "config"
    first = GitConfigParser(path, read_only=False)
    second = GitConfigParser(path, read_only=False)
    first.set_value("values", "one", 1)
    second.set_value("values", "two", 2)
    assert GitConfigParser(path).options("values") == ["one", "two"]
    lock = config_directory / "config.lock"
    lock.write_text("reserved")
    with pytest.raises(OSError):
        first.set_value("values", "one", 3)
    assert GitConfigParser(path).get_value("values", "one") == 1


@pytest.mark.parametrize(
    "scenario",
    [
        "missing",
        pytest.param("unwritable", marks=pytest.mark.skipif(os.name != "posix", reason="Requires POSIX permissions")),
    ],
)
def test_config_mutation_propagates_non_contention_lock_errors(scenario):
    # Native fixture copies reset directory permissions, losing the unwritable state.
    with writable_fixture("config.sh", "lock-errors", scenario, execute=scenario == "unwritable") as fixture:
        parent = fixture.path().resolve() / "parent"
        path = parent / "config"
        try:
            if scenario == "unwritable" and os.access(parent, os.W_OK):
                pytest.skip("Current user can write to read-only directories")
            with pytest.raises(GitCommandError) as baseline:
                Git().config("set", "--file", str(path), "--all", "--", "values.number", "1")
            assert "could not lock config file" in baseline.value.stderr
            # Writers acquire Git's lock during each mutation, not at construction.
            writer = GitConfigParser(path, read_only=False)
            with mock.patch.object(time, "sleep", side_effect=AssertionError("Must not retry")) as sleep:
                with pytest.raises(OSError) as error:
                    writer.set_value("values", "number", 1)
                sleep.assert_not_called()
            cause = error.value.__cause__
            assert isinstance(cause, GitCommandError)
            assert (cause.status, cause.stderr) == (baseline.value.status, baseline.value.stderr)
            assert str(error.value) == cause.stderr
            assert not path.exists()
            assert not path.with_suffix(".lock").exists()
        finally:
            if scenario == "unwritable":
                parent.chmod(0o700)


def test_config_section_constraint(config_directory):
    with SectionConstraint(GitConfigParser(config_directory / "config", read_only=False), 'remote "origin"') as remote:
        remote.set_value("url", "https://example.com/repo")
        remote.add_value("url", "ssh://example.com/repo")
        assert remote.get_values("url") == ["https://example.com/repo", "ssh://example.com/repo"]
        assert remote.options() == ["url"]


def test_config_invalid_syntax_is_rejected_by_git():
    path = read_only_fixture("config.sh", "invalid") / "config"
    with pytest.raises(configparser.ParsingError):
        GitConfigParser(path).read()


def test_config_stream_relative_include_has_no_file_base():
    with pytest.raises(configparser.ParsingError) as error:
        GitConfigParser(BytesIO(b"[include]\npath = relative\n")).read()
    assert isinstance(error.value.__cause__, GitCommandError)
    assert "relative config includes must come from files" in error.value.__cause__.stderr


@pytest.mark.parametrize(
    "case, expected",
    [
        (0, "one two"),
        (1, "one two"),
        (2, "one two\tthree"),
        (3, "one two # three"),
        (4, "value "),
        (5, "value "),
        (6, "value \t"),
        (7, "one two "),
        (8, None),
        (9, "val\\"),
    ],
)
def test_continued_values_follow_git_reads_and_writes(case, expected):
    with writable_fixture("config.sh", "continued-values", case) as fixture:
        path = fixture.path() / "config"
        baseline = fixture.path() / "baseline"
        if expected is None:
            with pytest.raises(GitCommandError, match="bad config line"):
                Git().config("get", "--file", str(baseline), "a.k")
            with GitConfigParser(path) as config, pytest.raises(configparser.ParsingError):
                config.get_value("a", "k")
            return
        assert Git().config("get", "--null", "--file", str(baseline), "a.k") == expected + "\0"
        with GitConfigParser(path, read_only=False) as config:
            assert config.get_value("a", "k") == expected
            config.set_value("other", "value", "updated")
        Git().config("set", "--file", str(baseline), "--all", "--", "other.value", "updated")
        assert path.read_bytes() == baseline.read_bytes()
        # Git appends the section header into a dangling EOF continuation.
        dangling = case in (4, 5, 6, 7)
        written_section = "a" if dangling else "other"
        after = expected + "[other]" if dangling else expected
        assert Git().config("get", "--null", "--file", str(baseline), "a.k") == after + "\0"
        with GitConfigParser(path) as config:
            assert config.get_value("a", "k") == after
            assert config.get_value(written_section, "value") == "updated"


@pytest.mark.parametrize(
    "option, expected",
    [
        ("hasnewline", "first\nsecond"),
        ("hastab", "first\tsecond"),
        ("hasbackslash", "foo\\bar"),
        ("hasquote", 'ab"cd'),
        ("hastrailingbackslash", "word\\"),
        ("ordinary", "hello world"),
        ("withcolon", "host:port"),
        ("withequals", "key=value"),
        ("withhash", "value"),
        ("hasunknownescape", None),
        ("haswindowspath", None),
    ],
)
def test_config_with_unquoted_escapes(option, expected):
    path = read_only_fixture("config.sh", "unquoted-escapes", fixture_path("git_config_unquoted_escapes")) / option
    if expected is None:
        with pytest.raises(GitCommandError, match="bad config line"):
            Git().config("get", "--file", str(path), "custom." + option)
        with GitConfigParser(path) as config, pytest.raises(configparser.ParsingError):
            config.get("custom", option)
        return
    assert Git().config("get", "--null", "--file", str(path), "custom." + option) == expected + "\0"
    with GitConfigParser(path) as config:
        assert config.get("custom", option) == expected
