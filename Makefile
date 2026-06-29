# Ventra developer convenience targets.
export PYTHONDONTWRITEBYTECODE := 1

UV ?= uv

.PHONY: help install dev-setup demo demo-azure demo-gcp ingest ingest-azure ingest-gcp backend frontend dev gui test lint readonly-guard validate-artifacts generate-catalog clean clean-pycache ensure-no-pycache install-hooks

help:
	@echo "Ventra targets:"
	@echo "  make install        Install collector + ingester + backend (editable)"
	@echo "  make gui            Same as: ventra gui (auto-setup + hot reload, no Docker)"
	@echo "  make demo           Generate AWS synthetic evidence package into tests/fixtures/"
	@echo "  make demo-azure     Generate Azure synthetic evidence package into tests/fixtures/"
	@echo "  make demo-gcp       Generate GCP synthetic evidence package into tests/fixtures/"
	@echo "  make ingest         Ingest the AWS demo package into ./cases"
	@echo "  make ingest-azure   Ingest the Azure demo package into ./cases"
	@echo "  make ingest-gcp     Ingest the GCP demo package into ./cases"
	@echo "  make backend        Run the console backend (uvicorn :8000, reload)"
	@echo "  make frontend       Run the console frontend (next dev :8080)"
	@echo "  make test           Run the Python test suite"
	@echo "  make lint           ruff + frontend typecheck"
	@echo "  make readonly-guard Verify the collector is read-only"
	@echo "  make validate-artifacts  Validate the artifact YAML catalog (CI gate)"
	@echo "  make generate-catalog    Regenerate console/frontend/lib/catalog.ts from artifacts/"
	@echo "  make clean-pycache    Remove all __pycache__ folders locally"

install:
	$(UV) sync

dev-setup: install clean-pycache ensure-no-pycache install-hooks
	mkdir -p cases .ventra-uploads
	cd console/frontend && npm install

gui: clean-pycache
	$(UV) run ventra gui

# Alias of `gui`, kept for muscle memory.
dev: gui

demo:
	$(UV) run python tests/fixtures/generate_demo_case.py --out tests/fixtures/

demo-azure:
	$(UV) run python tests/fixtures/generate_azure_demo_case.py --out tests/fixtures/

demo-gcp:
	$(UV) run python tests/fixtures/generate_gcp_demo_case.py --out tests/fixtures/

ingest:
	$(UV) run ventra-ingest tests/fixtures/case-CASE-2026-0042-*.tar.zst --case-store ./cases

ingest-azure:
	$(UV) run ventra-ingest $$(ls -t tests/fixtures/case-CASE-2026-AZ42-*.tar.zst | head -1) --case-store ./cases

ingest-gcp:
	$(UV) run ventra-ingest $$(ls -t tests/fixtures/case-CASE-*-gcp-*.tar.zst | head -1) --case-store ./cases

backend: clean-pycache
	VENTRA_CASE_STORE=./cases VENTRA_UPLOAD_DIR=./.ventra-uploads \
	$(UV) run uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

frontend:
	cd console/frontend && npm run dev

test: clean-pycache
	$(UV) run pytest tests/ -q

lint:
	$(UV) run ruff check collector ingester console/backend
	cd console/frontend && npm run typecheck

readonly-guard:
	$(UV) run python -m collector.tools.verify_readonly --collectors
	$(UV) run python -m collector.tools.verify_readonly docs/iam-policies/aws-collector-readonly.json

validate-artifacts:
	$(UV) run ventra artifacts validate

generate-catalog:
	$(UV) run python scripts/generate-catalog-ts.py

clean-pycache:
	@./scripts/clean-pycache.sh

ensure-no-pycache:
	@chmod +x scripts/ensure-no-pycache.sh && ./scripts/ensure-no-pycache.sh

install-hooks:
	@./scripts/install-git-hooks.sh

clean: clean-pycache
	rm -rf cases .ventra-uploads tests/fixtures/case-*.tar.* tests/fixtures/case-*.sha256
