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

        update_file = 'dir1/file2.txt' # we'll use ./dir1/file2.txt
        with open(f"{local_dir}/{update_file}", 'a') as f:
            f.write('\nUpdate version 2')
        # ![2-test_cloned_repo_object]

        # [3-test_cloned_repo_object]
        add_file = [f"{update_file}"] # relative path from git root
        repo.index.add(add_file)  # notice the add function requires a list of paths
        # ![3-test_cloned_repo_object]

        # code to commit - not sure how to test this
        # [4-test_cloned_repo_object]
        repo.index.commit("Update to file2")
        # ![4-test_cloned_repo_object]

        # [5-test_cloned_repo_object]
        file = 'dir1/file2.txt' # relative path from git root
        repo.iter_commits('--all', max_count=100, paths=file)

        # Outputs: <generator object Commit._iter_from_process_or_stream at 0x7fb66c186cf0>

        # ![5-test_cloned_repo_object]

        # [6-test_cloned_repo_object]
        commits_for_file_generator = repo.iter_commits('--all', max_count=100, paths=file)
        commits_for_file = [c for c in commits_for_file_generator]
        commits_for_file

        # Outputs: [<git.Commit "5076b368c97b01d83406ca095a301303da7f6fd4">,
        # <git.Commit "d8dcd544e6fc5c00f6984424fc0cb4568abe518e">]
        # ![6-test_cloned_repo_object]

        # Untracked files - create new file
        # [7-test_cloned_repo_object]
        # We'll create a file5.txt

        file5 = f'{local_dir}/file5.txt'
        with open(file5, 'w') as f:
            f.write('file5 version 1')
        # ![7-test_cloned_repo_object]

        # [8-test_cloned_repo_object]
        repo.untracked_files
        # Output: ['file5.txt']
        # ![8-test_cloned_repo_object]

        # Modified files
        # [9-test_cloned_repo_object]
        # Lets modify one of our tracked files
        file3 = f'{local_dir}/Downloads/file3.txt'
        with open(file3, 'w') as f:
            f.write('file3 version 2')  # overwrite file 3
        # ![9-test_cloned_repo_object]

        # [10-test_cloned_repo_object]
        repo.index.diff(None)
        # Output: [<git.diff.Diff object at 0x7fb66c076e50>,
        # <git.diff.Diff object at 0x7fb66c076ca0>]
        # ![10-test_cloned_repo_object]

        # [11-test_cloned_repo_object]
        diffs = repo.index.diff(None)
        for d in diffs:
            print(d.a_path)

        # Downloads/file3.txt
        # file4.txt
        # ![11-test_cloned_repo_object]

        '''Trees and Blobs'''

        # Latest commit tree
        # [12-test_cloned_repo_object]
        tree = repo.tree()
        # ![12-test_cloned_repo_object]

        # Previous commit tree
        # [13-test_cloned_repo_object]
        prev_commits = [c for c in repo.iter_commits('--all', max_count=10)]
        tree = prev_commits[0].tree
        # ![13-test_cloned_repo_object]

        # Iterating through tree
        # [14-test_cloned_repo_object]
        tree = repo.tree()
        files_dirs = [fd for fd in tree]
        files_dirs

        # Output
        # [<git.Tree "1d1cbc95a765e42bd46561f197eef01281a97ac0">,
        # <git.Tree "4ca53fd68b9a0eafd463c9681f1a26183a40779b">,
        # <git.Blob "9d384f1b6903ad992a97f91f720d8709b2b71f84">]

        # ![14-test_cloned_repo_object]

        # [15-test_cloned_repo_object]
        def print_files_from_git(tree, delim='-', i=0):
            files_dirs = [fd for fd in tree]
            for fd in files_dirs:
                print(f'{delim if i != 0 else ""}| {fd.path}, {fd.type}')
                if fd.type == "tree":
                    print_files_from_git(fd, delim * 4, i + 1)

        # ![15-test_cloned_repo_object]

        # [16-test_cloned_repo_object]
        print_files_from_git(tree)

        # Output
        # | Downloads, tree
        # ---- | Downloads / file3.txt, blob
        # | dir1, tree
        # ---- | dir1 / file1.txt, blob
        # ---- | dir1 / file2.txt, blob
        # | file4.txt, blob
        # # ![16-test_cloned_repo_object]

        # Printing text files
        # [17-test_cloned_repo_object]
        print_file = 'dir1/file2.txt'
        tree[print_file]

        # Output <git.Blob "3fab4a2e97ee374d0eccd854f298eee0b06a62fb">
        # ![17-test_cloned_repo_object]

        # [18-test_cloned_repo_object]
        blob = tree[print_file]
        print(blob.data_stream.read().decode())

        # Output
        # file 2 version 1
        # Update version 2

        # ![18-test_cloned_repo_object]


