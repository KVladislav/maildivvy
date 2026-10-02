# Maildivvy 0.1.2. The unit tests and the lint run locally, in seconds, and need no
# mail machine. A local .venv is used when present, otherwise the distribution's python3.
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
BIN ?= $(if $(wildcard .venv/bin/python),.venv/bin/,)
UNIT ?= tests/unit

.PHONY: test-unit lint

# pytest exits 5 when it collected no test, so an empty discovery fails the target.
test-unit:
	$(PYTHON) -m pytest $(UNIT)

# ansible-lint with .ansible-lint and its exceptions, then Ansible's own syntax check of
# the playbook the installer runs. The roles' own modules are in ansible/library.
lint:
	ANSIBLE_LIBRARY=ansible/library $(BIN)ansible-lint
	$(BIN)ansible-playbook --syntax-check -i ansible/local.yml ansible/site.yml
