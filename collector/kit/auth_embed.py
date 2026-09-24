"""Embed saved connection authentication into an acquisition kit staging tree."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .mint import mint_connection_credentials, write_minted_credentials

CREDENTIALS_DIR = "credentials"


def embed_connection_auth(staging: Path, conn: dict[str, Any], acq: dict[str, Any]) -> dict[str, Any]:
    """Write short-lived auth material into ``staging`` and annotate ``acq``.

    Returns the credential metadata dict suitable for ``kit.json`` ``credential``.
    """
    cloud = (acq.get("cloud") or conn.get("platform") or "").strip().lower()
    minted = mint_connection_credentials(conn, cloud=cloud)
    write_minted_credentials(staging, minted)
    for key, value in minted.acquisition_fields.items():
        if value is None or value == "":
            continue
        # Do not clobber explicit acquire-scope fields already set on the acquisition.
        if key in ("project", "subscription") and str(acq.get(key) or "").strip():
            continue
        acq[key] = value
    return minted.meta_dict()
