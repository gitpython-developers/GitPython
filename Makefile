.PHONY: all clean release force_release

all:
	@grep -Ee '^[a-z].*:' Makefile | cut -d: -f1 | grep -vF all

clean:
	rm -rf build/ dist/ .eggs/ .tox/

release: clean
	# Check that VERSION and changes.rst exist and have no uncommitted changes
	test -f VERSION
	test -f doc/source/changes.rst
	git status -s VERSION doc/source/changes.rst
	@test -z "$$(git status -s VERSION doc/source/changes.rst)"

	# Check that ALL changes are commited (can comment out if absolutely necessary)
	git status -s
	@test -z "$$(git status -s)"

	# Check that latest tag matches version and is the current head we're releasing
	@version_file="$$(cat VERSION)" && \
	changes_file="$$(awk '/^[0-9]/ {print $$0; exit}' doc/source/changes.rst)" && \
	config_opts="$$(printf ' -c versionsort.suffix=-%s' alpha beta pre rc RC)" && \
	latest_tag=$$(git $$config_opts tag -l '[0-9]*' --sort=-v:refname | head -n1) && \
	head_sha=$$(git rev-parse HEAD) latest_tag_sha=$$(git rev-parse "$$latest_tag") && \
	printf '%-14s = %s\n' 'VERSION file'   "$$version_file" \
	                      'changes.rst'    "$$changes_file" \
	                      'Latest tag'     "$$latest_tag" \
	                      'HEAD SHA'       "$$head_sha" \
	                      'Latest tag SHA' "$$latest_tag_sha" && \
	test "$$version_file" = "$$changes_file" && \
	test "$$latest_tag" = "$$version_file" && \
	test "$$head_sha" = "$$latest_tag_sha"

	make force_release

force_release: clean
	# IF we're in a virtual environment, add build tools
	test -z "$$VIRTUAL_ENV" || pip install -U build twine

	# Build the sdist and wheel that will be uploaded to PyPI.
	if test -n "$$VIRTUAL_ENV"; then \
		python -m build --sdist --wheel; \
	else \
		python3 -m build --sdist --wheel || \
		{ echo "Use a virtual-env with 'python -m venv env && source env/bin/activate' instead" && false; }; \
	fi

	# Upload to PyPI and push the tag.
	twine upload dist/*
	git push --tags origin main
