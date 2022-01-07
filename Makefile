.DEFAULT_GOAL := help
.PHONY: server-image help clean _env-info

_env-info:
	@echo "# Poetry: $$(type poetry) $$(poetry --version $$POETRY_ADDOPTS)"
	@echo "# Global Poetry configuration:"
	@poetry config --list $$POETRY_ADDOPTS
	@echo "# Local Poetry configuration:"
	@poetry config --list --local $$POETRY_ADDOPTS
	@echo "# Tox: $$(type tox) $$(tox --version)"

##@ Tests

##@ Documentation

##@ Release

server-image:  ## Build a Docker image with Artemis server.
	buildah bud -f container/Dockerfile .

##@ Utility

clean:  ## Remove installed virtual environment
	rm -rf .tox
	rm -rf .venv

# See https://www.thapaliya.com/en/writings/well-documented-makefiles/ for details.
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make [target]\033[36m\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
