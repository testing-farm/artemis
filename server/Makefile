.DEFAULT_GOAL := help
.PHONY: help install install-no-dev coverage test gen-db-revision publish clean

install:  ## Install Artemis and development tools
	poetry install -v

install-no-dev:  ## Install Artemis alone, no development tools
	poetry install -v --no-dev

coverage:  ## Run tests with coverage
	tox -e py37-coverage

test:  ## Run all tests
	tox

docs:
	tox -e autodocs

gen-db-revision:  ## Generate new DB revision
	rm -rf test.db
	poetry run alembic upgrade head
	poetry run alembic revision --autogenerate -m "$(NAME)"

publish:  ## Publish server package to PyPI
	@poetry publish --username $(PYPI_USERNAME) --password $(PYPI_PASSWORD) --build

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
