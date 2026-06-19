"""Importing this package registers every source normalizer."""

from . import gcp_audit  # noqa: F401
from . import gcp_findings  # noqa: F401
from . import access_logs  # noqa: F401
from . import azure_activity_log  # noqa: F401
from . import azure_diagnostics  # noqa: F401
from . import azure_entra  # noqa: F401
from . import azure_nsg_flow  # noqa: F401
from . import log_analytics  # noqa: F401
from . import cloudtrail  # noqa: F401
from . import dns_logs  # noqa: F401
from . import eks_audit  # noqa: F401
from . import findings  # noqa: F401
from . import m365  # noqa: F401
from . import network  # noqa: F401
from . import waf  # noqa: F401
