"""The configuration facade follows Git's parser and mutation semantics."""

import configparser
from collections import UserList
from io import BytesIO
from unittest import mock

import pytest

from git import Git, GitCommandError, GitConfigParser, Repo
from git.config import SectionConstraint


@pytest.mark.parametrize("stream", [False, True])
def test_config_values_and_mutations(tmp_path, stream):
    content = b'[CoRe]\nFlag\nnumber = 1\nnumber = 2\n[remote "Origin"]\nurl = first\n'
    path = tmp_path / "config"
    path.write_bytes(content)
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


def test_config_includes_and_repository_conditions(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    included = tmp_path / "included"
    included.write_text("[values]\nsource = included\n")
    config_path = tmp_path / "config"
    with GitConfigParser(config_path, read_only=False) as config:
        config.set_value("values", "source", "before")
        config.set_value("include", "path", str(included))
        config.add_value("values", "source", "after")
        config.set_value('includeIf "gitdir:' + repo.git_dir + '"', "path", str(included))
    assert GitConfigParser(config_path, repo=repo).get_values("values", "source") == [
        "before",
        "after",
        "included",
        "included",
    ]
    assert GitConfigParser(config_path, merge_includes=False).get_values("values", "source") == ["before", "after"]


def test_config_multiple_files_and_missing_values(tmp_path):
    one, two = tmp_path / "one", tmp_path / "two"
    one.write_text("[values]\nnumber = 1\n")
    two.write_text("[values]\nnumber = 2\n")
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
def test_config_values_are_literals(tmp_path, value):
    path = tmp_path / "config"
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
def test_config_rejects_invalid_fields_before_git(tmp_path, section, option, value):
    config = GitConfigParser(tmp_path / "config", read_only=False)
    with mock.patch.object(Git, "_call_process_safe", side_effect=AssertionError("Git must not run")):
        with pytest.raises(ValueError):
            config.set_value(section, option, value)


def test_config_writers_use_git_locking(tmp_path):
    path = tmp_path / "config"
    first = GitConfigParser(path, read_only=False)
    second = GitConfigParser(path, read_only=False)
    first.set_value("values", "one", 1)
    second.set_value("values", "two", 2)
    assert GitConfigParser(path).options("values") == ["one", "two"]
    lock = tmp_path / "config.lock"
    lock.write_text("reserved")
    with pytest.raises(OSError):
        first.set_value("values", "one", 3)
    assert GitConfigParser(path).get_value("values", "one") == 1


def test_config_section_constraint(tmp_path):
    with SectionConstraint(GitConfigParser(tmp_path / "config", read_only=False), 'remote "origin"') as remote:
        remote.set_value("url", "https://example.com/repo")
        remote.add_value("url", "ssh://example.com/repo")
        assert remote.get_values("url") == ["https://example.com/repo", "ssh://example.com/repo"]
        assert remote.options() == ["url"]


def test_config_invalid_syntax_is_rejected_by_git(tmp_path):
    path = tmp_path / "config"
    path.write_text("[values]\ninvalid_key = value\n")
    with pytest.raises(configparser.ParsingError):
        GitConfigParser(path).read()


def test_config_stream_relative_include_has_no_file_base():
    with pytest.raises(configparser.ParsingError) as error:
        GitConfigParser(BytesIO(b"[include]\npath = relative\n")).read()
    assert isinstance(error.value.__cause__, GitCommandError)
    assert "relative config includes must come from files" in error.value.__cause__.stderr
