#!/usr/bin/env bash
# Start local Elastic (Docker), install Ventra index template, load NDJSON via Logstash.
#
#   ./demo.sh                                    # cloudtrail only (fast)
#   ./demo.sh --all                              # every *.ndjson in export dir
#   EXPORT_DIR=~/Downloads/Test-AWS-elastic-export ./demo.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
EXPORT_DIR="${EXPORT_DIR:-$ROOT/export}"
LOAD_ALL=false
OPEN_KIBANA=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) LOAD_ALL=true; shift ;;
    --no-open) OPEN_KIBANA=false; shift ;;
    -h|--help)
      echo "Usage: EXPORT_DIR=path/to/export $0 [--all] [--no-open]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ ! -d "$EXPORT_DIR" ]]; then
  echo "Export directory not found: $EXPORT_DIR" >&2
  echo "Export a case first: ventra-export --case-dir cases/<id> --out ./export" >&2
  exit 1
fi

export PATH="/usr/local/bin:${PATH:-}"

echo "==> Starting Elasticsearch + Kibana..."
docker compose -f "$ROOT/docker-compose.yml" up -d elasticsearch kibana

echo "==> Waiting for Elasticsearch..."
for i in $(seq 1 60); do
  if curl -sf "http://localhost:9200/_cluster/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -sf "http://localhost:9200/_cluster/health?pretty" | head -5

echo "==> Installing Ventra index template..."
curl -sf -X PUT "http://localhost:9200/_index_template/ventra-events" \
  -H 'Content-Type: application/json' \
  -d @"$ROOT/ventra-events-template.json" >/dev/null
echo "    template ventra-events installed"

load_file() {
  local ndjson="$1"
  echo "==> Logstash ingest: $(basename "$ndjson")"
  EXPORT_DIR="$EXPORT_DIR" VENTRA_NDJSON="/export/$(basename "$ndjson")" \
    docker compose -f "$ROOT/docker-compose.yml" --profile ingest run --rm logstash
}

if $LOAD_ALL; then
  shopt -s nullglob
  files=("$EXPORT_DIR"/*.ndjson)
  if [[ ${#files[@]} -eq 0 ]]; then
    echo "No *.ndjson files in $EXPORT_DIR" >&2
    exit 1
  fi
  for f in "${files[@]}"; do
    load_file "$f"
  done
else
  if [[ -f "$EXPORT_DIR/cloudtrail.ndjson" ]]; then
    load_file "$EXPORT_DIR/cloudtrail.ndjson"
  else
    first="$(find "$EXPORT_DIR" -maxdepth 1 -name '*.ndjson' | head -1)"
    if [[ -z "$first" ]]; then
      echo "No NDJSON files in $EXPORT_DIR" >&2
      exit 1
    fi
    load_file "$first"
  fi
fi

echo ""
echo "==> Indices:"
curl -s "http://localhost:9200/_cat/indices/ventra-*?v"

echo ""
echo "==> Demo ready"
echo "    Kibana:    http://localhost:5601"
echo "    Discover:  create data view  ventra-*  (time field: @timestamp)"
echo "    Filter:    ventra.case_id : \"<your-case-id>\""
echo "    Security:  Kibana → Security (Elastic SIEM UI — Basic/dev features)"
echo ""
echo "Stop stack:  docker compose -f $ROOT/docker-compose.yml down"

if $OPEN_KIBANA; then
  open "http://localhost:5601/app/discover" 2>/dev/null || true
fi
