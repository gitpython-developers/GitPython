import subprocess
import sys

import git


_, working_dir, env_var_name = sys.argv

# Importing git should be enough, but this really makes sure Git.execute is called.
repo = git.Repo(working_dir)  # Hold the reference.
git.Git(repo.working_dir).execute(["git", "version"])

print(subprocess.check_output(["set", env_var_name], shell=True, text=True))
