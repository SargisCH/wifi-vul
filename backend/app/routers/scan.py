from fastapi import APIRouter, HTTPException
from librouteros.exceptions import TrapError, FatalError, ConnectionClosed

from app.services.mikrotik import (
    get_connection,
    fetch_wireless_interfaces,
    fetch_security_profiles,
    fetch_system_resource,
)
from app.services.scanner import run_scan, Severity
from app.models.scan import ScanResultOut, FindingOut

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.get("/wifi", response_model=ScanResultOut)
def scan_wifi():
    try:
        api = get_connection()
    except (ConnectionClosed, OSError, ConnectionRefusedError) as exc:
        raise HTTPException(status_code=503, detail=f"Cannot connect to MikroTik: {exc}")

    try:
        interfaces = fetch_wireless_interfaces(api)
        profiles = fetch_security_profiles(api)
        system_info = fetch_system_resource(api)
    except TrapError as exc:
        raise HTTPException(status_code=502, detail=f"MikroTik API error: {exc}")
    except FatalError as exc:
        raise HTTPException(status_code=401, detail=f"MikroTik auth error: {exc}")
    finally:
        try:
            api.close()
        except Exception:
            pass

    result = run_scan(interfaces, profiles, system_info)

    findings_out = [
        FindingOut(
            severity=f.severity,
            title=f.title,
            description=f.description,
            recommendation=f.recommendation,
            interface=f.interface,
            profile=f.profile,
        )
        for f in result.findings
    ]

    counts = {s: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity] += 1

    return ScanResultOut(
        score=result.score,
        findings=findings_out,
        interfaces=result.interfaces,
        security_profiles=result.security_profiles,
        total_findings=len(result.findings),
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
        routeros_version=result.routeros_version,
        wpa3_capable=result.wpa3_capable,
    )
