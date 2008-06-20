class InvalidGitRepositoryError(Exception):
    pass

class NoSuchPathError(Exception):
    pass

class GitCommandError(Exception):
    def __init__(self, command, status, stderr=None):
        self.stderr = stderr
        self.status = status
        self.command = command

    def __str__(self):
        return repr("%s returned exit status %d" %
                    (str(self.command), self.status))

