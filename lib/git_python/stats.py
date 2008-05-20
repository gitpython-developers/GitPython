class Stats(object):
    def __init__(self, repo, total, files):
        self.repo = repo
        self.total = total
        self.files = files

    @classmethod
    def list_from_string(cls, repo, text):
        hsh = {'total': {'insertions': 0, 'deletions': 0, 'lines': 0, 'files': 0}, 'files': {}}
        for line in text.splitlines():
            (insertions, deletions, filename) = line.split("\t")
            hsh['total']['insertions'] += int(insertions)
            hsh['total']['deletions'] += int(deletions)
            hsh['total']['lines'] = (hsh['total']['deletions'] + hsh['total']['insertions'])
            hsh['total']['files'] += 1
            hsh['files'][filename.strip()] = {'insertions': int(insertions), 'deletions': int(deletions)}
        return Stats(repo, hsh['total'], hsh['files'])
