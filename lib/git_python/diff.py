import re
import commit

class Diff(object):
    """
    A Diff contains diff information between two commits.
    """
    
    def __init__(self, repo, a_path, b_path, a_commit, b_commit, a_mode, b_mode, new_file, deleted_file, diff):
        self.repo = repo
        self.a_path = a_path
        self.b_path = b_path
        
        if not a_commit or re.search(r'^0{40}$', a_commit):
            self.a_commit = None
        else:
            self.a_commit = commit.Commit(repo, **{'id': a_commit})
        if not b_commit or re.search(r'^0{40}$', b_commit):
            self.b_commit = None
        else:
            self.b_commit = commit.Commit(repo, **{'id': b_commit})
        
        self.a_mode = a_mode
        self.b_mode = b_mode
        self.new_file = new_file
        self.deleted_file = deleted_file
        self.diff = diff
    
    @classmethod
    def list_from_string(cls, repo, text):
        lines = text.splitlines()
        a_mode = None
        b_mode = None
        diffs = []
        while lines:
            m = re.search(r'^diff --git a/(\S+) b/(\S+)$', lines.pop(0))
            if m:
                a_path, b_path = m.groups()
            if re.search(r'^old mode', lines[0]):
                m = re.search(r'^old mode (\d+)', lines.pop(0))
                if m:
                    a_mode, = m.groups()
                m = re.search(r'^new mode (\d+)', lines.pop(0))
                if m:
                    b_mode, = m.groups()
                if re.search(r'^diff --git', lines[0]):
                    diffs.append(Diff(repo, a_path, b_path, None, None, a_mode, b_mode, False, False, None))
                    continue
            
            new_file = False
            deleted_file = False
            
            if re.search(r'^new file', lines[0]):
                m = re.search(r'^new file mode (.+)', lines.pop(0))
                if m:
                    b_mode, = m.groups()
                a_mode = None
                new_file = True
            elif re.search(r'^deleted file', lines[0]):
                m = re.search(r'^deleted file mode (.+)$', lines.pop(0))
                if m:
                    a_mode, = m.groups()
                b_mode = None
                deleted_file = True
            
            m = re.search(r'^index ([0-9A-Fa-f]+)\.\.([0-9A-Fa-f]+) ?(.+)?$', lines.pop(0))
            if m:
                a_commit, b_commit, b_mode = m.groups()
            if b_mode:
                b_mode = b_mode.strip()
            
            diff_lines = []
            while lines and not re.search(r'^diff', lines[0]):
                diff_lines.append(lines.pop(0))
            
            diff = "\n".join(diff_lines)
            diffs.append(Diff(repo, a_path, b_path, a_commit, b_commit, a_mode, b_mode, new_file, deleted_file, diff))
        
        return diffs