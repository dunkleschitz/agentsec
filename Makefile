PYTHON ?= python3

.PHONY: test pages playground benchmark
test: ## Run every tool's test suite; fails if any suite fails or runs zero tests
	$(PYTHON) run_tests.py

pages: ## Regenerate docs/tools/* and sitemap.xml from tool READMEs
	$(PYTHON) scripts/generate_tool_pages.py

playground: ## Sync vendored playground tool sources into docs/playground/vendor/
	$(PYTHON) scripts/sync_playground.py

benchmark: ## Re-run the detection corpus and refresh docs/benchmarks/
	$(PYTHON) benchmarks/run_benchmark.py --write-pages
