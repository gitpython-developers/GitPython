from git import Repo


def get_active_branch(gitobj: Repo) -> str:
    return gitobj.active_branch.name


gitobj = Repo(".")
print(get_active_branch(gitobj))
