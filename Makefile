# Maildivvy 0.3.0. The unit tests, the Python lint and the Ansible lint run locally, in seconds, and need no
# mail machine. A local .venv is used when present, otherwise the distribution's python3.
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
BIN ?= $(if $(wildcard .venv/bin/python),.venv/bin/,)
UNIT ?= tests/unit

.PHONY: test-unit lint

# ruff first, with pyproject.toml's rules; then pytest, which exits 5 when it collected no
# test, so an empty discovery fails the target.
test-unit:
	$(BIN)ruff check --no-cache
	$(PYTHON) -m pytest $(UNIT)

# ansible-lint with .ansible-lint and its exceptions, then Ansible's own syntax check of
# the playbook the installer runs. The roles' own modules are in ansible/library.
lint:
	ANSIBLE_LIBRARY=ansible/library $(BIN)ansible-lint
	$(BIN)ansible-playbook --syntax-check -i ansible/local.yml ansible/site.yml
