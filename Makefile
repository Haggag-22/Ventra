# Harbor developer convenience targets.
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: help install dev-setup demo ingest backend frontend dev console test lint readonly-guard clean clean-pycache ensure-no-pycache install-hooks

help:
	@echo "Harbor targets:"
	@echo "  make install        Install collector + ingester + backend (editable)"
	@echo "  make dev-setup      install + npm deps + local dirs (one-time)"
	@echo "  make dev            Run backend + frontend locally (live reload)"
	@echo "  make demo           Generate a synthetic evidence package into tests/fixtures/"
	@echo "  make ingest         Ingest the demo package into ./cases"
	@echo "  make backend        Run the console backend (uvicorn :8000, reload)"
	@echo "  make frontend       Run the console frontend (next dev :8080)"
	@echo "  make console        docker compose up the full stack"
	@echo "  make test           Run the Python test suite"
	@echo "  make lint           ruff + frontend typecheck"
	@echo "  make readonly-guard Verify the collector is read-only"
	@echo "  make clean-pycache    Remove all __pycache__ folders locally"

install:
	pip install -e .[dev] -e ./ingester[dev] -e ./console/backend

dev-setup: install clean-pycache ensure-no-pycache install-hooks
	mkdir -p cases .harbor-uploads
	cd console/frontend && npm install

dev: clean-pycache
	./scripts/dev-local.sh

demo:
	python tests/fixtures/generate_demo_case.py --out tests/fixtures/

ingest:
	harbor-ingest tests/fixtures/case-*.tar.zst --case-store ./cases

backend: clean-pycache
	HARBOR_CASE_STORE=./cases HARBOR_UPLOAD_DIR=./.harbor-uploads \
	uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

frontend:
	cd console/frontend && npm run dev

console:
	docker compose -f deploy/compose/harbor.yml up --build

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
	rm -rf cases .harbor-uploads tests/fixtures/case-*.tar.* tests/fixtures/case-*.sha256
