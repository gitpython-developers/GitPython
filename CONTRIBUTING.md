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

## Prevent agent impersonation

AI agents communicating through a person's account must identify themselves, for
example in issue or PR descriptions and comments. AI assistance that does not replace
the person as the speaker, such as proofreading or wording polish, does not require
identification.

Attributing AI assistance in commit metadata, for example with a `Co-authored-by`
trailer, is welcome but not required. Code is reviewed the same way regardless of its
origin.

## Fuzzing Test Specific Documentation

For details related to contributing to the fuzzing test suite and OSS-Fuzz integration, please 
refer to the dedicated [fuzzing README](./fuzzing/README.md).
