# Ventra developer convenience targets.
export PYTHONDONTWRITEBYTECODE := 1

UV ?= uv

.PHONY: help install dev-setup demo demo-azure demo-gcp demo-kubernetes aws-lab-deploy aws-lab-seed aws-lab-destroy ingest ingest-azure ingest-gcp ingest-kubernetes backend frontend dev gui test lint readonly-guard validate-artifacts generate-catalog clean clean-pycache ensure-no-pycache install-hooks

help:
	@echo "Ventra targets:"
	@echo "  make install        Install collector + ingester + backend (editable)"
	@echo "  make gui            Same as: ventra gui (auto-setup + hot reload, no Docker)"
	@echo "  make demo           Generate AWS synthetic evidence package into tests/fixtures/"
	@echo "  make demo-azure     Generate Azure synthetic evidence package into tests/fixtures/"
	@echo "  make demo-gcp       Generate GCP synthetic evidence package into tests/fixtures/"
	@echo "  make aws-lab-deploy Deploy live AWS collector lab (terraform)"
	@echo "  make aws-lab-seed   Seed attack story activity in the lab"
	@echo "  make aws-lab-destroy Tear down AWS collector lab"
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
	@# macOS (esp. iCloud Desktop) may mark editable install files UF_HIDDEN;
	@# Python then skips *.pth and the ventra console script cannot import collector.
	@if [ "$$(uname -s)" = Darwin ]; then \
		find .venv/lib \( -name '__editable__*' -o -name '*.pth' \) \
			-exec chflags nohidden {} + 2>/dev/null || true; \
	fi

dev-setup: install clean-pycache ensure-no-pycache install-hooks
	mkdir -p cases .ventra-uploads
	cd console/frontend && npm install

gui: clean-pycache
	@# Desktop/iCloud marks editable *.pth UF_HIDDEN; PYTHONPATH avoids that entirely.
	PYTHONPATH="$(CURDIR):$(CURDIR)/ingester$${PYTHONPATH:+:$$PYTHONPATH}" \
		$(UV) run python -m collector.cli gui

# Alias of `gui`, kept for muscle memory.
dev: gui

demo:
	$(UV) run python tests/fixtures/generate_demo_case.py --out tests/fixtures/

demo-azure:
	$(UV) run python tests/fixtures/generate_azure_demo_case.py --out tests/fixtures/

demo-gcp:
	$(UV) run python tests/fixtures/generate_gcp_demo_case.py --out tests/fixtures/

demo-kubernetes:
	$(UV) run python tests/fixtures/generate_kubernetes_demo_case.py --out tests/fixtures/

aws-lab-deploy:
	cd docs/deployment/aws/collector-lab/terraform && terraform init -input=false && terraform apply -input=false -auto-approve

aws-lab-seed:
	$(UV) run python docs/deployment/aws/collector-lab/seed/seed_attack_story.py

aws-lab-destroy:
	cd docs/deployment/aws/collector-lab/terraform && terraform destroy -input=false -auto-approve

ingest:
	PYTHONPATH=$(CURDIR):$(CURDIR)/ingester $(UV) run ventra-ingest tests/fixtures/case-CASE-2026-0042-*.tar.zst --case-store ./cases

ingest-azure:
	PYTHONPATH=$(CURDIR):$(CURDIR)/ingester $(UV) run ventra-ingest $$(ls -t tests/fixtures/case-CASE-2026-AZ42-*.tar.zst | head -1) --case-store ./cases

ingest-gcp:
	PYTHONPATH=$(CURDIR):$(CURDIR)/ingester $(UV) run ventra-ingest $$(ls -t tests/fixtures/case-CASE-*-gcp-*.tar.zst | head -1) --case-store ./cases

ingest-kubernetes:
	PYTHONPATH=$(CURDIR):$(CURDIR)/ingester $(UV) run ventra-ingest $$(ls -t tests/fixtures/case-CASE-2026-K8S1-*.tar.zst | head -1) --case-store ./cases

backend: clean-pycache
	cd console/backend && PYTHONPATH=$(CURDIR):$(CURDIR)/ingester VENTRA_CASE_STORE=$(CURDIR)/cases VENTRA_UPLOAD_DIR=$(CURDIR)/.ventra-uploads \
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
