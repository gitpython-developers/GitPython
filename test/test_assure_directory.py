from pathlib import Path

import pytest

from git.util import assure_directory_exists
from test.lib.fixtures import writable_fixture


@pytest.fixture
def directory_fixture(monkeypatch):
    with writable_fixture("assure-directory.sh") as temporary:
        directory = temporary.path().resolve()
        with monkeypatch.context() as context:
            context.chdir(directory)
            yield directory


@pytest.mark.parametrize("path_type", [str, Path])
def test_file_in_current_directory_already_has_parent(directory_fixture, path_type):
    assert assure_directory_exists(path_type("notes.txt"), is_file=True) is False
    assert not (directory_fixture / "notes.txt").exists()


@pytest.mark.parametrize("path_type", [str, Path])
def test_nested_file_creates_only_missing_parent_directories(directory_fixture, path_type):
    filename = path_type("new/nested/notes.txt")
    assert assure_directory_exists(filename, is_file=True) is True
    assert (directory_fixture / "new/nested").is_dir()
    assert not (directory_fixture / "new/nested/notes.txt").exists()
    assert assure_directory_exists(filename, is_file=True) is False


@pytest.mark.parametrize("path_type", [str, Path])
def test_existing_directory_is_unchanged(directory_fixture, path_type):
    assert assure_directory_exists(path_type("existing")) is False


@pytest.mark.parametrize("path_type", [str, Path])
def test_file_cannot_be_used_as_parent_directory(directory_fixture, path_type):
    with pytest.raises(FileExistsError):
        assure_directory_exists(path_type("blocked/notes.txt"), is_file=True)
    assert (directory_fixture / "blocked").read_text() == "occupied\n"
