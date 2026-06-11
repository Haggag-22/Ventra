"""Harbor collector — read-only cloud forensic triage acquisition.

The collector runs in the client's cloud shell, gathers exactly the logs and artifacts
incident responders need, and seals them into a signed evidence package described by the
Harbor Evidence Package Format (EPF).

Forensic invariant: nothing in this package may call a mutating cloud API. See
``harbor_collector.tools.verify_readonly`` and the ``readonly-guard`` CI check.
"""

__version__ = "0.1.0"
