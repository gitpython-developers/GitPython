# Contribution guidelines

Before starting work, read and follow [CONTRIBUTING.md](CONTRIBUTING.md),
including the [Prevent agent impersonation](CONTRIBUTING.md#prevent-agent-impersonation)
section governing identification when communicating through a person's account.

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
