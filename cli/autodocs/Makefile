# Minimal makefile for Sphinx documentation
#
# Artemis documentation build Makefile, created by
# sphinx-quickstart on Sun Sep 27 19:29:52 2020.
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = Artemis
SOURCEDIR     = source
BUILDDIR      = build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help apidoc Makefile

apidoc:
	cd ../ && sphinx-apidoc -T -e -o autodocs/source -f --implicit-namespaces src/tft

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
