import pytest


from test.lib import TestBase
from test.lib.helper import with_rw_directory


class QuickDoc(TestBase):
    def tearDown(self):
        import gc

        gc.collect()

    @with_rw_directory
    def test_init_repo_object(self, path_to_dir):

        # [1-test_init_repo_object]
        # $ git init <path/to/dir>

        from git import Repo

        repo = Repo.init(path_to_dir)  # git init path/to/dir
       # ![1-test_init_repo_object]

        # [2-test_init_repo_object]
        repo = Repo(path_to_dir)
        # ![2-test_init_repo_object]

    @with_rw_directory
    def test_cloned_repo_object(self, local_dir):

        from git import Repo
        import git
        # code to clone from url
        # [1-test_cloned_repo_object]
        # $ git clone <url> <local_dir>

        repo_url = "https://github.com/gitpython-developers/QuickStartTutorialFiles.git"

        repo = Repo.clone_from(repo_url, local_dir)
        # ![1-test_cloned_repo_object]

        # code to add files
        # [2-test_cloned_repo_object]
        # We must make a change to a file so that we can add the update to git

        update_file = 'dir1/file2.txt' # we'll use local_dir/dir1/file2.txt
        with open(f"{local_dir}/{update_file}", 'a') as f:
            f.write('\nUpdate version 2')
        # ![2-test_cloned_repo_object]

        # [3-test_cloned_repo_object]
        # $ git add <file>
        add_file = [update_file]  # relative path from git root
        repo.index.add(add_file)  # notice the add function requires a list of paths
        # ![3-test_cloned_repo_object]

        # code to commit - not sure how to test this
        # [4-test_cloned_repo_object]
        # $ git commit -m <message>
        repo.index.commit("Update to file2")
        # ![4-test_cloned_repo_object]

        # [5-test_cloned_repo_object]
        # $ git log <file>

        # relative path from git root
        repo.iter_commits(all=True, max_count=10, paths=update_file)  # gets the last 10 commits from all branches

        # Outputs: <generator object Commit._iter_from_process_or_stream at 0x7fb66c186cf0>

        # ![5-test_cloned_repo_object]

        # [6-test_cloned_repo_object]
        commits_for_file_generator = repo.iter_commits(all=True, max_count=10, paths=update_file)
        commits_for_file = [c for c in commits_for_file_generator]
        commits_for_file

        # Outputs: [<git.Commit "SHA1-HEX_HASH-2">,
        # <git.Commit "SHA1-HEX-HASH-2">]
        # ![6-test_cloned_repo_object]

        # Untracked files - create new file
        # [7-test_cloned_repo_object]
        f = open(f'{local_dir}/untracked.txt', 'w')  # creates an empty file
        f.close()
        # ![7-test_cloned_repo_object]

        # [8-test_cloned_repo_object]
        repo.untracked_files
        # Output: ['untracked.txt']
        # ![8-test_cloned_repo_object]

        # Modified files
        # [9-test_cloned_repo_object]
        # Let's modify one of our tracked files

        with open(f'{local_dir}/Downloads/file3.txt', 'w') as f:
            f.write('file3 version 2')  # overwrite file 3
        # ![9-test_cloned_repo_object]

        # [10-test_cloned_repo_object]
        repo.index.diff(None)  # compares staging area to working directory
        repo.index.diff(repo.head.commit)  # compares staging area to last commit
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
        tree = repo.head.commit.tree
        # ![12-test_cloned_repo_object]

        # Previous commit tree
        # [13-test_cloned_repo_object]
        prev_commits = [c for c in repo.iter_commits(all=True, max_count=10)]  # last 10 commits from all branches
        tree = prev_commits[0].tree
        # ![13-test_cloned_repo_object]

        # Iterating through tree
        # [14-test_cloned_repo_object]
        files_and_dirs = [entry for entry in tree]
        files_and_dirs

        # Output
        # [<git.Commit "SHA1-HEX_HASH">,
        # <git.Commit "SHA1-HEX_HASH">,
        # <git.Commit "SHA1-HEX_HASH">]

        # ![14-test_cloned_repo_object]

        # [14.1-test_cloned_repo_object]
        files_and_dirs = [(entry, entry.name) for entry in tree]
        files_and_dirs

        # Output
        # [(< git.Tree "SHA1-HEX_HASH" >, 'Downloads', 'tree'),
        #  (< git.Tree "SHA1-HEX_HASH" >, 'dir1', 'tree'),
        #  (< git.Blob "SHA1-HEX_HASH" >, 'file4.txt', 'blob')]
        # ![14.1-test_cloned_repo_object]

        # [15-test_cloned_repo_object]
        def print_files_from_git(root, level=0):
            for entry in root:
                print(f'{"-" * 4 * level}| {entry.path}, {entry.type}')
                if entry.type == "tree":
                    print_files_from_git(entry, level + 1)

        # ![15-test_cloned_repo_object]

        # [16-test_cloned_repo_object]
        print_files_from_git(tree)

        # Output
        # | Downloads, tree
        # ----| Downloads / file3.txt, blob
        # | dir1, tree
        # ----| dir1 / file1.txt, blob
        # ----| dir1 / file2.txt, blob
        # | file4.txt, blob
        # # ![16-test_cloned_repo_object]

        # Printing text files
        # [17-test_cloned_repo_object]
        print_file = 'dir1/file2.txt'
        tree[print_file]  # the head commit tree

        # Output <git.Blob "SHA1-HEX-HASH-1">
        # ![17-test_cloned_repo_object]

        # print latest file
        # [18-test_cloned_repo_object]
        blob = tree[print_file]
        print(blob.data_stream.read().decode())

        # Output
        # file 2 version 1
        # Update version 2
        # ![18-test_cloned_repo_object]

        # print previous tree
        # [18.1-test_cloned_repo_object]
        commits_for_file = [c for c in repo.iter_commits(all=True, paths=print_file)]
        tree = commits_for_file[-1].tree  # gets the first commit tree
        blob = tree[print_file]

        print(blob.data_stream.read().decode())

        # Output
        # file 2 version 1
        # ![18.1-test_cloned_repo_object]