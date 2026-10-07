# Contribution guidelines

Before starting work, read and follow [CONTRIBUTING.md](CONTRIBUTING.md),
including the [Prevent agent impersonation](CONTRIBUTING.md#prevent-agent-impersonation)
section governing identification when communicating through a person's account.

# Gix backend implementations

Gix backend operations must use Gix through the supported GixPython (`gix`)
APIs. Python/stdlib implementations, direct filesystem inference, and custom
native implementations outside Gix are not substitutes for a missing Gix
operation. Do not implement Git behavior independently to avoid CLI calls.

"Native" in code, documentation, reports and benchmarks means execution by
Gitoxide through GixPython's `gix` API. It never means Python-implemented Git
behavior. Every eliminated CLI call must be backed by identified Gix calls.

Python glue may validate inputs, adapt Gix results to GitPython's return types
and formatting, manage the retained `gix.Repository`, and select a CLI fallback.
It must not invent a successful result or repair missing Git semantics with a
separate implementation. Retaining and explicitly recreating a Gix repository
through the shared accessor is allowed.

Adapting native locations may append the fixed metadata leaf names `modules`
and `COMMIT_EDITMSG` to `Repository.git_dir()`, whose location Gix resolves.
Input paths may be canonicalized before reopening through Gix; return metadata
from that native handle. These adaptations must match Git in regression tests
and do not authorize a Python implementation of the general `--git-path` rules.

If Gix lacks a capability, differs from the required behavior, or its use is
unclear, keep the existing Git CLI path and document the gap in
`doc/gix-backend.md`. State the expected behavior, available evidence, and what
GixPython or Gitoxide needs to expose or fix upstream. Tests, coverage reports
and benchmark ceilings must reflect that fallback; a lower CLI count alone
does not demonstrate a Gix implementation.

Track every observed difference from the equivalent Git operation as a Git
compatibility bug, even if the Gix behavior is intentional. Gix must provide
matching behavior, at least through a mode as strict as Git. Record Git's
expected behavior, Gix's actual behavior, versions, reproduction or regression,
and the affected adapter/fallback in the ledger. Keep these bugs open when a
Gix-based adapter workaround restores parity; close them only after verifying
the upstream fix or compatible mode. Distinguish demonstrated mismatches from
missing APIs and unverified behavior. Do not repair a compatibility bug by
implementing Git semantics in Python.

# Commit messages

Follow Conventional Commits for every commit. Every commit must have a
descriptive title and a substantive body. Title-only commit messages are not
acceptable.

## Formatting

Write commit messages in Markdown and assume readers view them with syntax
highlighting. Enclose code identifiers, package and module names, file paths,
and shell commands in backticks. Use Markdown whenever it helps readers
understand or navigate the prose.

## Titles

- Every title must use the form `type: description` or
  `type(scope): description`.
- Use `feat:` for user-visible features and `fix:` for user-visible fixes.
- Use appropriate prefixes for other changes, such as `docs:`, `test:`, `ci:`,
  `build:`, `refactor:`, `perf:`, `style:`, or `chore:`.
- Breaking changes must use `!` immediately before the colon, for example
  `feat!:`, `refactor!:`, or a scoped form such as `fix(repo)!:`.
- Optionally scope a commit to the affected component, for example `fix(repo):`.

Example titles:

- `feat: add support for a new Git option`
- `fix(repo): handle bare repositories correctly`
- `build!: drop support for an older Python version`
- `ci: add an independent documentation build`
- `refactor(repo): simplify repository initialization`

## Body

The body must explain the problem or motivation, what changed, and why the
chosen approach addresses it. Include relevant behavior before and after the
change, design decisions, limitations, and validation results. Scale the detail
to the change; do not add boilerplate or claim checks that were not run.

Commit messages must stand on their own. Put the information needed to understand
and review the change in the commit body, even when it also appears in a pull
request description. PR and issue links may provide additional context, but must
not substitute for that explanation.
