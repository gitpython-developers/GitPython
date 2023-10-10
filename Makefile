.PHONY: all lint clean release force_release

all:
	@awk -F: '/^[[:alpha:]].*:/ && !/^all:/ {print $$1}' Makefile

lint:
	SKIP=black-format pre-commit run --all-files --hook-stage manual

clean:
	rm -rf build/ dist/ .eggs/ .tox/

release: clean
	./check-version.sh
	make force_release

force_release: clean
	./build-release.sh
	twine upload dist/*
	git push --tags origin main
