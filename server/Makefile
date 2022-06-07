.DEFAULT_GOAL := help
.PHONY: help install install-no-dev coverage gen-db-revision publish clean _env-info

# Poetry does not handle "default" flavor of Python, and uses the most recent one. That's nice,
# but we like to be in control, knowing what exactl we did install.
DEFAULT_PYTHON ?= python3.7

_env-info:
	@echo "# Poetry: $$(type poetry) $$(poetry --version $$POETRY_ADDOPTS)"
	@echo "# Global Poetry configuration:"
	@poetry config --list $$POETRY_ADDOPTS
	@echo "# Local Poetry configuration:"
	@poetry config --list --local $$POETRY_ADDOPTS
	@echo "# Tox: $$(type tox) $$(tox --version)"

##@ Installation

install: _env-info  ## Install Artemis and development tools
	poetry env use $(DEFAULT_PYTHON) $$POETRY_ADDOPTS
	poetry env info $$POETRY_ADDOPTS
	poetry install -v --remove-untracked $$POETRY_ADDOPTS

install-no-dev: _env-info  ## Install Artemis alone, no development tools
	poetry env use $(DEFAULT_PYTHON) $$POETRY_ADDOPTS
	poetry env info $$POETRY_ADDOPTS
	poetry install -v --no-dev --remove-untracked $$POETRY_ADDOPTS

##@ Tests

tests: test-units test-db-revisions test-pre-commit test-integration  ## Run all tests

test-units: _env-info  ## Run unit tests
	tox -e py37

test-db-schema-revisions:  _env-info  ## Verify DB schema revisions
	tox -e py37-db-schema-revisions

test-pre-commit: install  ## Run pre-commit checks
	git ls-files -- . | xargs -n200 poetry run pre-commit run --files


INTEGRATION_POSTGRES_HOSTNAME := "localhost"
INTEGRATION_POSTGRES_PORT := "5432"
INTEGRATION_POSTGRES_USER := "artemis"
INTEGRATION_POSTGRES_PASSWORD := artemis
INTEGRATION_POSTGRES_DATABASE := "unit_test_db"
INTEGRATION_POSTGRES_URI := "postgresql://$(INTEGRATION_POSTGRES_USER):$(INTEGRATION_POSTGRES_PASSWORD)@$(INTEGRATION_POSTGRES_HOSTNAME):$(INTEGRATION_POSTGRES_PORT)/$(INTEGRATION_POSTGRES_DATABASE)"

test-integration: _env-info  ## Run tests against real services
	# Spawn the real processes, and we have a bunch of them handy
	docker-compose up -d postgres

	# Wait for PostgreSQL to become available
	while /bin/true; do \
	    pg_isready --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT); \
	    if [[ "$$?" == "0" ]]; then break; fi; \
	    sleep 1; \
	done

	# Our user lacks power to create database, grant it that right. Another option would be to have a dedicated user
	# for managing DBs, but that would require greater rework of how tests are handling DB.
	PGPASSWORD=mysecretpassword psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U postgres -c "DROP DATABASE IF EXISTS $(INTEGRATION_POSTGRES_DATABASE)"
	PGPASSWORD=mysecretpassword psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U postgres -c "ALTER USER $(INTEGRATION_POSTGRES_USER) CREATEDB"
	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "CREATE DATABASE $(INTEGRATION_POSTGRES_DATABASE)"

	# Unit tests
	tox -e py37 -- -x --against-db-url="$(INTEGRATION_POSTGRES_URI)"

	# DB schema upgrade/downgrade
	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "CREATE DATABASE $(INTEGRATION_POSTGRES_DATABASE)"
	ARTEMIS_DB_URL="$(INTEGRATION_POSTGRES_URI)" tox -e py37-db-schema-revisions
	PGPASSWORD=mysecretpassword psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U postgres -c "DROP DATABASE IF EXISTS $(INTEGRATION_POSTGRES_DATABASE)"

	docker-compose down

coverage: _env-info  ## Run tests with coverage
	tox -e py37-coverage

gen-db-revision:  ## Generate new DB revision
	rm -rf test.db
	poetry run alembic upgrade head
	poetry run alembic revision --autogenerate -m "$(NAME)"

##@ Documentation

docs: docs-autodocs docs-knobs  ## Generate all documentation

docs-autodocs:  ## Generate source code documentation
	tox -e autodocs

docs-knobs: install  ## Generate up-to-date documentation of knobs
	ARTEMIS_VAULT_PASSWORD=dummy-password poetry run ./extract-knobs --template-file ../docs/content/for-admins/knobs.adoc.j2 > ../docs/content/for-admins/knobs.adoc

##@ Release

publish:  ## Publish server package to PyPI
	@poetry publish --username $(PYPI_USERNAME) --password $(PYPI_PASSWORD) --build $$POETRY_ADDOPTS

##@ Utility

clean:  ## Remove installed virtual environment
	rm -rf .tox
	rm -rf .venv

# See https://www.thapaliya.com/en/writings/well-documented-makefiles/ for details.
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make [target]\033[36m\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
