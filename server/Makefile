.DEFAULT_GOAL := help
.PHONY: help install install-no-dev coverage test gen-db-revision publish clean _env-info

_env-info:
	@echo "# Poetry: $$(type poetry) $$(poetry --version $$POETRY_ADDOPTS)"
	@echo "# Global Poetry configuration:"
	@poetry config --list $$POETRY_ADDOPTS
	@echo "# Local Poetry configuration:"
	@poetry config --list --local $$POETRY_ADDOPTS
	@echo "# Tox: $$(type tox) $$(tox --version)"

install: _env-info  ## Install Artemis and development tools
	poetry install -v --remove-untracked $$POETRY_ADDOPTS

install-no-dev: _env-info  ## Install Artemis alone, no development tools
	poetry install -v --no-dev --remove-untracked $$POETRY_ADDOPTS

coverage: _env-info  ## Run tests with coverage
	tox -e py37-coverage

test: _env-info  ## Run all tests
	tox

test-pre-commit: install  ## Run pre-commit checks
	git ls-files -- . | xargs -n200 poetry run pre-commit run --files

integration-tests: _env-info  ## Run tests against real services
	# Spawn the real processes, and we have a bunch of them handy
	docker-compose up -d postgres

	# Wait for PostgreSQL to become available
	while /bin/true; do \
	    pg_isready --host 127.0.0.1 --port 5432; \
	    if [[ "$$?" == "0" ]]; then break; fi; \
	    sleep 1; \
	done

	# Our user lacks power to create database, grant it that right. Another option would be to have a dedicated user
	# for managing DBs, but that would require greater rework of how tests are handling DB.
	PGPASSWORD=mysecretpassword psql --host 127.0.0.1 --port 5432 -U postgres -c "ALTER USER artemis CREATEDB"

	# Unit tests
	tox -e py37 -- --against-db-url="postgresql://artemis:artemis@127.0.0.1:5432/unit_test_db"

	# DB schema upgrade/downgrade
	ARTEMIS_DB_URL="postgresql://artemis:artemis@127.0.0.1:5432/artemis" tox -e py37-database-migrations

	docker-compose down

docs: docs-autodocs docs-knobs  ## Generate all documentation

docs-autodocs:  ## Generate source code documentation
	tox -e autodocs

docs-knobs: install  ## Generate up-to-date documentation of knobs
	ARTEMIS_VAULT_PASSWORD=dummy-password poetry run ./extract-knobs --template-file ../docs/content/for-admins/knobs.adoc.j2 > ../docs/content/for-admins/knobs.adoc

gen-db-revision:  ## Generate new DB revision
	rm -rf test.db
	poetry run alembic upgrade head
	poetry run alembic revision --autogenerate -m "$(NAME)"

publish:  ## Publish server package to PyPI
	@poetry publish --username $(PYPI_USERNAME) --password $(PYPI_PASSWORD) --build $$POETRY_ADDOPTS

clean:  ## Remove installed virtual environment
	rm -rf .tox
	rm -rf .venv

help:  ## Show this help
	@IFS=$$'\n' ; \
	help_lines=(`fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##/:/' | sort`); \
	printf "%s\n\n" "Usage: make [task]"; \
	printf "%-20s %s\n" "task" "help" ; \
	printf "%-20s %s\n" "------" "----" ; \
	for help_line in $${help_lines[@]}; do \
		IFS=$$':' ; \
		help_split=($$help_line) ; \
		help_command=`echo $${help_split[0]} | sed -e 's/^ *//' -e 's/ *$$//'` ; \
		help_info=`echo $${help_split[2]} | sed -e 's/^ *//' -e 's/ *$$//'` ; \
		printf '\033[36m'; \
		printf "%-20s %s" $$help_command ; \
		printf '\033[0m'; \
		printf "%s\n" $$help_info; \
	done
