DEFAULT_PYTHON ?= python3.7

include ../Makefile.lib

.PHONY: .common-phony

##@ -- CLI targets ------------------------

test-units: _env-info  ## Run unit tests
	tox -e py37
