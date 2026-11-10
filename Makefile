PYTHON ?= python3

.PHONY: test pages
test: ## Run every tool's test suite; fails if any suite fails or runs zero tests
	$(PYTHON) run_tests.py

pages: ## Regenerate docs/tools/* and sitemap.xml from tool READMEs
	$(PYTHON) scripts/generate_tool_pages.py
