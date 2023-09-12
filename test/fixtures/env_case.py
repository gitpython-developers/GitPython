# Steps 3 and 4 for test_it_avoids_upcasing_unrelated_environment_variable_names.

import subprocess
import sys

# Step 3a: Import the module, in case that upcases the environment variable name.
import git


_, working_dir, env_var_name = sys.argv

# Step 3b: Use Git.execute explicitly, in case that upcases the environment variable.
#          (Importing git should be enough, but this ensures Git.execute is called.)
repo = git.Repo(working_dir)  # Hold the reference.
git.Git(repo.working_dir).execute(["git", "version"])

# Step 4: Create the non-Python grandchild that accesses the variable case-sensitively.
print(subprocess.check_output(["set", env_var_name], shell=True, text=True))
