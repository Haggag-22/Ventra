"""Azure + Microsoft 365 collectors.

Mirrors the AWS tier: a client factory that abstracts auth and the two Azure collection
paths (Graph / ARM management APIs, and diagnostic-settings-routed resource logs), a
registry, a runner, and pure collectors that return ``SourceResult``. The evidence-package
format, signing, and unified-event schema are shared with AWS unchanged.
"""
