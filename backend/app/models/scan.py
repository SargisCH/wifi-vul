from pydantic import BaseModel
from app.services.scanner import Severity


class FindingOut(BaseModel):
    severity: Severity
    title: str
    description: str
    recommendation: str
    interface: str | None = None
    profile: str | None = None


class ScanResultOut(BaseModel):
    score: int
    findings: list[FindingOut]
    interfaces: list[dict]
    security_profiles: list[dict]
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    routeros_version: str
    wpa3_capable: bool
