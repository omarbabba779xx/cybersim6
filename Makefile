# ─────────────────────────────────────────────────────────
# CyberSim6 — Makefile
# ─────────────────────────────────────────────────────────

.PHONY: help install dev test coverage lint demo dashboard sandbox clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install CyberSim6
	pip install -e .

dev: ## Install with dev dependencies (pytest, coverage)
	pip install -e ".[dev]"

test: ## Run all 436 tests
	python -m pytest tests/ -v

coverage: ## Run tests with HTML coverage report
	python -m pytest tests/ --cov=cybersim --cov-report=html --cov-report=term
	@echo "\n  Coverage report: htmlcov/index.html"

lint: ## Check code style with flake8
	python -m flake8 cybersim/ --max-line-length=120 --statistics

demo: ## Run automated demo (all 6 modules)
	python -m cybersim demo

dashboard: ## Start the web dashboard on port 8888
	python -m cybersim dashboard

sandbox: ## Setup the sandbox environment
	python -m cybersim sandbox setup

clean: ## Remove build artifacts and cache
	rm -rf build/ dist/ *.egg-info .pytest_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "  Cleaned."

version: ## Show current version
	python -m cybersim --version
