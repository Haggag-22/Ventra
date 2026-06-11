# Harbor console backend + ingester. Runs on the IR workstation; no outbound calls.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HARBOR_CASE_STORE=/data/cases \
    HARBOR_UPLOAD_DIR=/data/uploads

WORKDIR /app

# Install the ingester (parsers/normalizer/loaders) and the backend.
COPY ingester /app/ingester
COPY console/backend /app/console/backend
COPY schemas /app/schemas

RUN pip install ./ingester ./console/backend

VOLUME ["/data"]
EXPOSE 8000

# Bind to 0.0.0.0 inside the container; expose only on localhost via compose.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
