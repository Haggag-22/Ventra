# ventra/auth/store.py

import os
import json
from pathlib import Path

VENTRA_DIR = os.path.expanduser("~/.ventra")
VENTRA_CRED_PATH = os.path.join(VENTRA_DIR, "credentials.json")


def _load_store():
    """Load the Ventra credential store from disk."""
    if not os.path.exists(VENTRA_CRED_PATH):
        return {"active_profile": None, "profiles": {}}

    with open(VENTRA_CRED_PATH, "r") as f:
        return json.load(f)


def _save_store(store):
    """Write credential store to disk."""
    Path(VENTRA_DIR).mkdir(parents=True, exist_ok=True)

    with open(VENTRA_CRED_PATH, "w") as f:
        json.dump(store, f, indent=4)


def save_ventra_profile(profile, access_key, secret_key, region):
    """Create or update a Ventra internal AWS profile."""
    store = _load_store()

    store["profiles"][profile] = {
        "access_key": access_key,
        "secret_key": secret_key,
        "region": region
    }

    store["active_profile"] = profile

    _save_store(store)

    print(f"[✓] Saved Ventra profile '{profile}' → {VENTRA_CRED_PATH}")


def load_ventra_creds(profile=None):
    """
    Return credentials dict for the given profile, or active profile if None.
    """
    store = _load_store()

    # Determine active or given profile
    active = profile or store.get("active_profile")

    if not active:
        raise RuntimeError(
            "No active Ventra profile configured. Run 'ventra auth --profile ...' first."
        )

    profiles = store.get("profiles", {})

    if active not in profiles:
        raise RuntimeError(
            f"Profile '{active}' not found in Ventra credentials store."
        )

    return profiles[active]


def get_active_profile():
    """Return (active_profile_name, profile_credentials)."""
    store = _load_store()
    active = store.get("active_profile")

    if not active:
        raise RuntimeError(
            "No active Ventra profile configured. Run 'ventra auth --profile ...' first."
        )

    profiles = store.get("profiles", {})
    if active not in profiles:
        raise RuntimeError(
            f"Active profile '{active}' not found in Ventra credentials store."
        )

    return active, profiles[active]