include ../Makefile.lib

.PHONY: .common-phony coverage gen-db-revision

##@ -- Server targets ---------------------

##@ Tests

tests: .common-tests test-db-schema-revisions test-integration

test-db-schema-revisions:  _env-info  ## Verify DB schema revisions
	tox -e py37-db-schema-revisions

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

gen-db-revision:  ## Generate new DB revision
	rm -rf test.db
	poetry run alembic upgrade head
	poetry run alembic revision --autogenerate -m "$(NAME)"

##@ Documentation

docs: .common-docs docs-knobs

docs-knobs: install  ## Generate up-to-date documentation of knobs
	ARTEMIS_VAULT_PASSWORD=dummy-password poetry run ./extract-knobs --template-file ../docs/content/for-admins/knobs.adoc.j2 > ../docs/content/for-admins/knobs.adoc
