"""Harbor analyst console backend.

A thin FastAPI layer over the case store the ingester produces. It never calls out to the
cloud; it only reads ``cases/<id>/`` (events.parquet via DuckDB + the JSON sidecars). RBAC is
enforced here, server-side. No telemetry.
"""

__version__ = "0.1.0"
