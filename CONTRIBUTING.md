# Contributing

Issues and pull requests are welcome.

## How a pull request is merged

This repository is published from Maildivvy's development repository, one commit per
release. It is never edited here directly. A pull request is therefore not merged on
GitHub: it is ported into the development repository as a patch that keeps your
authorship, and it reaches this repository with the next release. The pull request is
then closed with a note naming the release that carries it, and the changelog lists it.

## Before you open one

- The checks need Python 3.14 and the packages CI installs, at the versions
  `.github/workflows/ci.yml` pins. In a virtual environment at the repository's root,
  which the Makefile uses when it is there:

  ```
  python3.14 -m venv .venv
  .venv/bin/pip install pytest==9.0.2 pyyaml==6.0.3 flask==3.1.3 jinja2==3.1.6 \
      ansible-core==2.20.1 ansible-lint==26.9.0
  ```
- Run the unit tests: `make test-unit`. They run locally in seconds and need no mail
  machine. A change to the programs or the roles comes with its test.
- Keep a pull request to one change. Say what it fixes or adds and why.
- Changes to the installation roles should still pass `make lint`: `ansible-lint`, with
  the exceptions `.ansible-lint-ignore` lists and says why, and
  `ansible-playbook --syntax-check`. The CI runs `make test-unit` and `make lint` on
  every push and pull request.
- The installation and mail-path tests run on a disposable machine before each release,
  so a change to the machine's behaviour may be adjusted when it is ported.
- Report a security problem privately, as [the security policy](SECURITY.md) says, not in
  a pull request.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
