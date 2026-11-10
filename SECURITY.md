# Security Policy

## Supported Versions

Only the latest version of GitPython can receive security updates. If a vulnerability is discovered, a fix can be issued in a new release.

| Version | Supported          |
| ------- | ------------------ |
| 3.x.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Threat Model

GitPython inherits its threat model directly from Git. The trust boundaries in
[Git's security documentation](https://github.com/git/git/blob/master/Documentation/git.adoc#security)
apply to both the CLI and Gix backends:

- **Repository content may be untrusted.** Cloning an untrusted repository and
  inspecting its history are supported operations. A clone creates local
  repository metadata without copying the source repository's configuration or
  hooks. Tracked files, including `.gitmodules`, remain untrusted input.
- **Local repository metadata must be trusted.** Running commands in an
  attacker-supplied `.git` directory, bare repository, or surrounding worktree is
  unsafe: configuration and hooks can execute commands. This includes repositories
  received in archives or copied directories. Owning the extracted files or listing
  a repository in `safe.directory` does not make its contents trustworthy.
- **Repository paths are not a sandbox.** Git supports metadata and working trees
  in [separate locations](https://github.com/git/git/blob/master/Documentation/git-clone.adoc),
  including metadata reached through gitfiles or symlinks.
  GitPython does not promise that all filesystem access stays within a checkout
  or `.git` directory. Paths supplied by untrusted repository content must still
  receive Git's intended protections.

For an untrusted repository directory, Git recommends obtaining a clean copy with
`git clone --no-local` before running other commands. Serving the source through
`git-upload-pack` still has an attack surface; Git recommends using an
unprivileged user for additional isolation. See
[Git's `git-upload-pack` security guidance](https://github.com/git/git/blob/master/Documentation/git-upload-pack.adoc#security).

`git.cmd.Git`, also exposed as `repo.git`, is a low-level command wrapper: it
runs the Git command with the arguments and options the caller supplies. It does
what it is told, including file reads, writes, or command execution requested
through those options. These explicitly requested effects are intended command
behavior, not unwanted side effects. For example,
`repo.git.checkout(pathspec_from_file=path)` asks Git to read `path` as pathspec
input, and Git's diagnostics may include that input. Applications exposing this
interface to untrusted callers must restrict commands, arguments, and options
and control which output and errors they disclose.

Higher-level methods, such as `Head.checkout()` and `Repo.clone_from()`, provide
specific operations and apply protections against options or operands that
introduce unwanted side effects beyond those operations. Where supported,
callers can explicitly opt into unsafe behavior. These protections do not
restrict direct calls through the command wrapper; bypasses of higher-level
protections remain reportable.

Violations of these trust boundaries or bypasses of Git's intended protections
remain reportable, including cases where Git itself is affected.

## Reporting a Vulnerability

Please report private portions of a vulnerability to <https://github.com/gitpython-developers/GitPython/security/advisories/new>. Doing so helps to receive updates and collaborate on the matter, without disclosing it publicly right away.

Vulnerabilities in GitPython's dependencies [gitdb](https://github.com/gitpython-developers/gitdb/blob/master/SECURITY.md) or [smmap](https://github.com/gitpython-developers/smmap/blob/master/SECURITY.md), which primarily exist to support GitPython, can be reported here as well, at that same link. The affected package (`GitPython`, `gitdb`, or `smmap`) can be included in the report, if known.
