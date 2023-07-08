import pytest

import git
from test.lib import TestBase
from test.lib.helper import with_rw_directory


class QuickDoc(TestBase):
    def tearDown(self):
        import gc

        gc.collect()

    @with_rw_directory
    def test_init_repo_object(self, rw_dir):
        path_to_dir = rw_dir

        # [1-test_init_repo_object]
        from git import Repo

        repo = Repo.init(path_to_dir)
        assert repo.__class__ is Repo # Test to confirm repo was initialized
        # ![1-test_init_repo_object]

        # [2-test_init_repo_object]
        try:
            repo = Repo(path_to_dir)
        except git.NoSuchPathError:
            assert False, f"No such path {path_to_dir}"
        # ! [2-test_init_repo_object]

        # [3 - test_init_repo_object]

