# Security Policy

## Supported Versions

Only the latest version of GitPython can receive security updates. If a vulnerability is discovered, a fix can be issued in a new release.

| Version | Supported          |
| ------- | ------------------ |
| 3.x.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Reporting a Vulnerability

Please report private portions of a vulnerability to <https://github.com/gitpython-developers/GitPython/security/advisories/new>. Doing so helps to receive updates and collaborate on the matter, without disclosing it publicly right away.

Vulnerabilities in GitPython's dependencies [gitdb](https://github.com/gitpython-developers/gitdb/blob/master/SECURITY.md) or [smmap](https://github.com/gitpython-developers/smmap/blob/master/SECURITY.md), which primarily exist to support GitPython, can be reported here as well, at that same link. The affected package (`GitPython`, `gitdb`, or `smmap`) can be included in the report, if known.
