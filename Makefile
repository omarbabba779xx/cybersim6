.PHONY: help install dev test coverage lint typecheck precommit demo dashboard sandbox clean version

help: ## Show this help
	python tools/project_tasks.py help

install: ## Install CyberSim6
	pip install -e .

dev: ## Install with dev dependencies and tooling
	pip install -e ".[dev]"

test: ## Run all 704 tests
	python -m pytest tests/ -v

coverage: ## Run tests with HTML coverage report (85% minimum)
	python -m pytest tests/ --cov=cybersim --cov-report=html --cov-report=term --cov-fail-under=85
	@echo "\n  Coverage report: htmlcov/index.html"

lint: ## Check code style with flake8
	python -m flake8 cybersim/ --max-line-length=120 --statistics

typecheck: ## Run mypy on maintained modules
	python -m mypy --config-file pyproject.toml

precommit: ## Run pre-commit hooks across the repository
	python -m pre_commit run --all-files

demo: ## Run automated demo (all 6 attack modules)
	python -m cybersim demo

dashboard: ## Start the web dashboard on port 8888
	python -m cybersim dashboard

sandbox: ## Setup the sandbox environment
	python -m cybersim sandbox setup

clean: ## Remove build artifacts and cache
	python tools/project_tasks.py clean

version: ## Show current version
	python -m cybersim --version
