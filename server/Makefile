include ../Makefile.lib

.PHONY: .common-phony coverage gen-db-revision

##@ -- Server targets ---------------------

##@ Installation

install-no-drivers: _env-info  ## Install component alone, no development tools, no driver requirements
	poetry env use $(DEFAULT_PYTHON) $$POETRY_ADDOPTS
	poetry env info $$POETRY_ADDOPTS
	poetry install -v --no-dev --remove-untracked $$POETRY_ADDOPTS


##@ Tests

tests: .common-tests test-db-schema-revisions test-integration

test-units: _env-info  ## Run unit tests
	tox -e py312

coverage: _env-info  ## Run tests with coverage
	tox -e py312-coverage

INTEGRATION_POSTGRES_HOSTNAME := "localhost"
INTEGRATION_POSTGRES_PORT := "5432"
INTEGRATION_POSTGRES_USER := "artemis"
INTEGRATION_POSTGRES_PASSWORD := artemis
INTEGRATION_POSTGRES_DATABASE := "unit_test_db"
INTEGRATION_POSTGRES_URI := "postgresql://$(INTEGRATION_POSTGRES_USER):$(INTEGRATION_POSTGRES_PASSWORD)@$(INTEGRATION_POSTGRES_HOSTNAME):$(INTEGRATION_POSTGRES_PORT)/$(INTEGRATION_POSTGRES_DATABASE)"

test-integration: _env-info  ## Run tests against real services
	# Spawn the real processes, and we have a bunch of them handy
	podman-compose up -d postgresql

	# Wait for PostgreSQL to become available
	while /bin/true; do \
	    pg_isready --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT); \
	    if [[ "$$?" == "0" ]]; then break; fi; \
	    sleep 1; \
	done

	# Unit tests
	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "DROP DATABASE IF EXISTS $(INTEGRATION_POSTGRES_DATABASE)"
	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "CREATE DATABASE $(INTEGRATION_POSTGRES_DATABASE)"

	tox -e py312 -- -x --against-db-url="$(INTEGRATION_POSTGRES_URI)"

	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "DROP DATABASE IF EXISTS $(INTEGRATION_POSTGRES_DATABASE)"

	podman-compose down postgresql

test-db-schema-revisions:  _env-info  ## Verify DB schema revisions
	# Spawn the real processes, and we have a bunch of them handy
	podman-compose up -d postgresql

	# Wait for PostgreSQL to become available
	while /bin/true; do \
	    pg_isready --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT); \
	    if [[ "$$?" == "0" ]]; then break; fi; \
	    sleep 1; \
	done

	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "DROP DATABASE IF EXISTS $(INTEGRATION_POSTGRES_DATABASE)"
	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "CREATE DATABASE $(INTEGRATION_POSTGRES_DATABASE)"

	ARTEMIS_DB_URL="$(INTEGRATION_POSTGRES_URI)" ARTEMIS_VAULT_PASSWORD=dummy-vault-password poetry run alembic upgrade head
	ARTEMIS_DB_URL="$(INTEGRATION_POSTGRES_URI)" ARTEMIS_VAULT_PASSWORD=dummy-vault-password poetry run alembic revision --autogenerate &> autogenerate.log

	@echo "--- autogenerate.log ---"
	@cat autogenerate.log
	@echo "------------------------"
	@grep "No changes to schema detected" autogenerate.log || bash -c "echo 'Untracked schema changes detected.'; exit 1"

	ARTEMIS_DB_URL="$(INTEGRATION_POSTGRES_URI)" ARTEMIS_VAULT_PASSWORD=dummy-vault-password poetry run alembic downgrade base

	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "DROP DATABASE IF EXISTS $(INTEGRATION_POSTGRES_DATABASE)"

	podman-compose down postgresql

gen-db-revision:  ## Generate new DB revision
	# Spawn the real processes, and we have a bunch of them handy
	podman-compose up -d postgresql

	# Wait for PostgreSQL to become available
	while /bin/true; do \
	    pg_isready --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT); \
	    if [[ "$$?" == "0" ]]; then break; fi; \
	    sleep 1; \
	done

	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "DROP DATABASE IF EXISTS $(INTEGRATION_POSTGRES_DATABASE)"
	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "CREATE DATABASE $(INTEGRATION_POSTGRES_DATABASE)"

	ARTEMIS_DB_URL="$(INTEGRATION_POSTGRES_URI)" ARTEMIS_VAULT_PASSWORD=dummy-vault-password poetry run alembic upgrade head
	ARTEMIS_DB_URL="$(INTEGRATION_POSTGRES_URI)" ARTEMIS_VAULT_PASSWORD=dummy-vault-password poetry run alembic revision --autogenerate -m "$(NAME)"

	PGPASSWORD=$(INTEGRATION_POSTGRES_PASSWORD) psql --host $(INTEGRATION_POSTGRES_HOSTNAME) --port $(INTEGRATION_POSTGRES_PORT) -U $(INTEGRATION_POSTGRES_USER) -c "DROP DATABASE IF EXISTS $(INTEGRATION_POSTGRES_DATABASE)"

	podman-compose down postgresql


##@ Documentation

docs: .common-docs docs-knobs

docs-knobs: install  ## Generate up-to-date documentation of knobs
	ARTEMIS_DB_URL=sqlite:// ARTEMIS_VAULT_PASSWORD=dummy-password poetry run ./extract-knobs --template-file ../docs/content/for-admins/knobs.adoc.j2 > ../docs/content/for-admins/knobs.adoc
