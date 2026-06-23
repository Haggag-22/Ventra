"""Role-based access control modelling DFIR separation of duties.

Four roles, mapped from AWS forensic guidance: Responder (acquires), Investigator (analyzes),
Data Custodian (manages evidence lifecycle), Analyst (reports/read-only). Capabilities are
enforced server-side. For local single-analyst use the default role is ``investigator``; a
deployment can wire real auth (OIDC) by populating the ``X-Ventra-Role`` claim upstream.
"""

from __future__ import annotations

import enum

from fastapi import Header, HTTPException


class Role(str, enum.Enum):
    RESPONDER = "responder"
    INVESTIGATOR = "investigator"
    DATA_CUSTODIAN = "data_custodian"
    ANALYST = "analyst"


# capability -> roles allowed
CAPABILITIES: dict[str, set[Role]] = {
    "view_case": {Role.INVESTIGATOR, Role.ANALYST, Role.DATA_CUSTODIAN, Role.RESPONDER},
    "import_case": {Role.INVESTIGATOR, Role.DATA_CUSTODIAN},
    "delete_case": {Role.DATA_CUSTODIAN},
    "export_report": {Role.INVESTIGATOR, Role.ANALYST, Role.DATA_CUSTODIAN},
    "view_audit": {Role.DATA_CUSTODIAN, Role.INVESTIGATOR},
    # Building an acquisition kit is the Responder's job (acquisition phase).
    "build_acquisition": {Role.RESPONDER, Role.INVESTIGATOR, Role.DATA_CUSTODIAN},
}


def current_role(x_ventra_role: str | None = Header(default=None)) -> Role:
    if not x_ventra_role:
        return Role.INVESTIGATOR  # local default
    try:
        return Role(x_ventra_role.lower())
    except ValueError:
        raise HTTPException(status_code=403, detail=f"Unknown role: {x_ventra_role}")


def _check(capability: str):
    from fastapi import Depends

    def _inner(role: Role = Depends(current_role)) -> Role:
        allowed = CAPABILITIES.get(capability, set())
        if role not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{role.value}' lacks capability '{capability}'.",
            )
        return role

    return _inner
