DEFAULT_PYTHON ?= python3.9

include ../Makefile.lib

.PHONY: .common-phony

##@ -- CLI targets ------------------------

test-units: _env-info  ## Run unit tests
	tox -e py39
