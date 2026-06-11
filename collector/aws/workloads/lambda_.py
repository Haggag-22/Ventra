"""Lambda collector (Tier 2).

Function inventory with resource policies and (redacted) environment configuration. Lambda is
a common persistence and exfil vector — attacker-created functions, over-broad resource
policies allowing cross-account invoke, and secrets in environment variables. Secret-looking
env values are redacted in the package; their *keys* are kept so analysts know they existed.
"""

from __future__ import annotations

import re

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled

_SECRET_KEY = re.compile(r"(secret|token|password|passwd|key|cred)", re.I)


class LambdaCollector(Collector):
    name = "lambda"
    tier = 2
    description = "Lambda function inventory, resource policies, redacted env config."
    required_actions = ("lambda:ListFunctions", "lambda:GetFunction", "lambda:GetPolicy")

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        functions: list[dict] = []

        for region in self.ctx.regions:
            try:
                for fn in cf.paginate("lambda", region, "list_functions", "Functions"):
                    fn = dict(fn)
                    fn["_harbor_region"] = region
                    self._redact_env(fn)
                    arn = fn.get("FunctionArn")
                    try:
                        fn["ResourcePolicy"] = cf.call(
                            "lambda", region, "get_policy", FunctionName=arn
                        ).get("Policy")
                    except (AccessDenied, ServiceNotEnabled):
                        fn["ResourcePolicy"] = None
                    functions.append(fn)
            except AccessDenied as exc:
                gaps.append(("lambda", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except ServiceNotEnabled:
                continue

        if not functions:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("lambda", GapReason.NOT_PRESENT, "No Lambda functions in scope.")],
                notes="No Lambda functions found.",
            )

        wf = self.write_json({"functions": functions}, "snapshot.json")
        self.write_meta({"source": self.name, "functions": len(functions)})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            record_count=len(functions),
            gaps=gaps,
            notes=f"{len(functions)} function(s).",
        )

    @staticmethod
    def _redact_env(fn: dict) -> None:
        env = fn.get("Environment", {}).get("Variables")
        if isinstance(env, dict):
            fn["Environment"]["Variables"] = {
                k: ("<redacted>" if _SECRET_KEY.search(k) else v) for k, v in env.items()
            }
