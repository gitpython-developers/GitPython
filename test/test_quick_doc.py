import pytest


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

        repo = Repo.init(path_to_dir)  # git init path/to/dir
        assert repo.__class__ is Repo  # Test to confirm repo was initialized
        # ![1-test_init_repo_object]

        # [2-test_init_repo_object]
        import git

        try:
            repo = Repo(path_to_dir)
        except git.NoSuchPathError:
            assert False, f"No such path {path_to_dir}"
        # ![2-test_init_repo_object]

    @with_rw_directory
    def test_cloned_repo_object(self, rw_dir):
        local_dir = rw_dir

        from git import Repo
        import git
        # code to clone from url
        # [1-test_cloned_repo_object]
        repo_url = "https://github.com/LeoDaCoda/GitPython-TestFileSys.git"

        try:
            repo = Repo.clone_from(repo_url, local_dir)
        except git.CommandError:
            assert False, f"Invalid address {repo_url}"
        # ![1-test_cloned_repo_object]

        # code to add files
        # [2-test_cloned_repo_object]
        # We must make a change to a file so that we can add the update to git

        update_file = 'dir1/file2.txt' # we'll use /dir1/file2.txt
        with open(f"{local_dir}/{update_file}", 'a') as f:
            f.write('\nUpdate version 2')
        # ![2-test_cloned_repo_object]

        # [3-test_cloned_repo_object]
        add_file = [f"{local_dir}/{update_file}"]
        repo.index.add(add_file)  # notice the add function requires a list of paths
        # [3-test_cloned_repo_object]

