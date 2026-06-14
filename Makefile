# Ventra developer convenience targets.
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: help install dev-setup demo ingest backend frontend dev gui test lint readonly-guard clean clean-pycache ensure-no-pycache install-hooks

help:
	@echo "Ventra targets:"
	@echo "  make install        Install collector + ingester + backend (editable)"
	@echo "  make gui            Same as: ventra gui (auto-setup + hot reload, no Docker)"
	@echo "  make demo           Generate a synthetic evidence package into tests/fixtures/"
	@echo "  make ingest         Ingest the demo package into ./cases"
	@echo "  make backend        Run the console backend (uvicorn :8000, reload)"
	@echo "  make frontend       Run the console frontend (next dev :8080)"
	@echo "  make test           Run the Python test suite"
	@echo "  make lint           ruff + frontend typecheck"
	@echo "  make readonly-guard Verify the collector is read-only"
	@echo "  make clean-pycache    Remove all __pycache__ folders locally"

install:
	pip install -e .[dev] -e ./ingester[dev] -e ./console/backend

dev-setup: install clean-pycache ensure-no-pycache install-hooks
	mkdir -p cases .ventra-uploads
	cd console/frontend && npm install

gui: clean-pycache
	ventra gui

# Alias of `gui`, kept for muscle memory.
dev: gui

demo:
	python tests/fixtures/generate_demo_case.py --out tests/fixtures/

ingest:
	ventra-ingest tests/fixtures/case-*.tar.zst --case-store ./cases

backend: clean-pycache
	VENTRA_CASE_STORE=./cases VENTRA_UPLOAD_DIR=./.ventra-uploads \
	uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

frontend:
	cd console/frontend && npm run dev

test: clean-pycache
	pytest tests/ -q

lint:
	ruff check collector ingester console/backend
	cd console/frontend && npm run typecheck

readonly-guard:
	python -m collector.tools.verify_readonly --collectors
	python -m collector.tools.verify_readonly docs/iam-policies/aws-collector-readonly.json

clean-pycache:
	@./scripts/clean-pycache.sh

ensure-no-pycache:
	@chmod +x scripts/ensure-no-pycache.sh && ./scripts/ensure-no-pycache.sh

install-hooks:
	@./scripts/install-git-hooks.sh

clean: clean-pycache
	rm -rf cases .ventra-uploads tests/fixtures/case-*.tar.* tests/fixtures/case-*.sha256
