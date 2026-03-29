from librouteros import connect
from librouteros.exceptions import TrapError, FatalError
from app.config import settings


def get_connection():
    """Create and return a MikroTik API connection."""
    return connect(
        host=settings.mikrotik_host,
        port=settings.mikrotik_port,
        username=settings.mikrotik_user,
        password=settings.mikrotik_password,
    )


def fetch_wireless_interfaces(api) -> list[dict]:
    """Fetch all wireless interfaces."""
    return list(api("/interface/wireless/print"))


def fetch_security_profiles(api) -> list[dict]:
    """Fetch all wireless security profiles."""
    return list(api("/interface/wireless/security-profiles/print"))


def fetch_access_list(api) -> list[dict]:
    """Fetch wireless access list (MAC filter rules)."""
    return list(api("/interface/wireless/access-list/print"))


def fetch_registration_table(api) -> list[dict]:
    """Fetch currently connected wireless clients."""
    return list(api("/interface/wireless/registration-table/print"))


def fetch_system_resource(api) -> dict:
    """Fetch system resource info (includes RouterOS version)."""
    rows = list(api("/system/resource/print"))
    return rows[0] if rows else {}
