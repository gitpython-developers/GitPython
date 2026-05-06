# How to contribute

The following is a short step-by-step rundown of what one typically would do to contribute.

- [Fork this project](https://github.com/gitpython-developers/GitPython/fork) on GitHub.
- For setting up the environment to run the self tests, please run `init-tests-after-clone.sh`.
- Please try to **write a test that fails unless the contribution is present.**
- Try to avoid massive commits and prefer to take small steps, with one commit for each.
- Feel free to add yourself to AUTHORS file.
- Create a pull request.

## Quality expectations

Contributions must be made with care and meet the quality bar of the surrounding code.
That means a change should not leave GitPython worse than it was before: it should be
readable, maintainable, tested where practical, documented and consistent with the
existing style and behavior.

A contribution that works only narrowly but lowers the quality of the
codebase may be declined. The maintainers may not always be able to provide
detailed feedback.

## AI-assisted contributions

If AI edits files for you, disclose it in the pull request description and commit
metadata. Prefer making the agent identity part of the commit, for example by using
an AI author such as `$agent $version <ai-agent@example.invalid>` or a co-author via
a `Co-authored-by: <agent-identity>` trailer.

Agents operating through a person's GitHub account must identify themselves. For
example, comments posted by an agent should say so directly with phrases like
`AI agent on behalf of <person>: ...`.

Fully AI-generated comments on pull requests or issues must also be disclosed.
Undisclosed AI-generated comments may lead to the pull request or issue being closed.

AI-assisted proofreading or wording polish does not need disclosure, but it is still
courteous to mention it when the AI materially influenced the final text.

Automated or "full-auto" AI contributions without a human responsible for reviewing
and standing behind the work may be closed.

## Fuzzing Test Specific Documentation

For details related to contributing to the fuzzing test suite and OSS-Fuzz integration, please 
refer to the dedicated [fuzzing README](./fuzzing/README.md).
