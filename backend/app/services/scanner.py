from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    severity: Severity
    title: str
    description: str
    recommendation: str
    interface: str | None = None
    profile: str | None = None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    interfaces: list[dict] = field(default_factory=list)
    security_profiles: list[dict] = field(default_factory=list)
    routeros_version: str = ""
    wpa3_capable: bool = False

    def add(self, finding: Finding):
        self.findings.append(finding)

    @property
    def score(self) -> int:
        """Security score 0–100 (100 = best)."""
        deductions = {
            Severity.CRITICAL: 30,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        total = sum(deductions[f.severity] for f in self.findings)
        return max(0, 100 - total)


# ---------------------------------------------------------------------------
# Security profile checks
# ---------------------------------------------------------------------------

WEAK_CIPHERS = {"none", "tkip"}
WEAK_AUTH_MODES = {"none", "wep-static", "wep-shared"}
WPA2_ONLY_MODES = {"wpa2-psk", "wpa2-eap"}
WPA3_MODES = {"wpa3-psk", "owe", "wpa3-eap"}


def check_security_profiles(profiles: list[dict], result: ScanResult):
    for profile in profiles:
        name = profile.get("name", "unknown")
        mode = profile.get("mode", "none")
        auth_types = profile.get("authentication-types", "")
        unicast_ciphers = str(profile.get("unicast-ciphers", "") or "")
        group_ciphers = str(profile.get("group-ciphers", "") or "")
        wpa_pre_shared_key = str(profile.get("wpa-pre-shared-key", "") or "")
        wpa2_pre_shared_key = str(profile.get("wpa2-pre-shared-key", "") or "")
        mfp = profile.get("management-protection", "disabled")

        # --- Open / no security ---
        if mode == "none":
            result.add(Finding(
                severity=Severity.CRITICAL,
                title="Open network (no encryption)",
                description=f"Security profile '{name}' has no authentication. All traffic is unencrypted.",
                recommendation="Enable WPA2 or WPA3 with a strong passphrase.",
                profile=name,
            ))
            continue

        # --- Legacy WEP ---
        if mode in WEAK_AUTH_MODES:
            result.add(Finding(
                severity=Severity.CRITICAL,
                title=f"Obsolete encryption: {mode.upper()}",
                description=f"Profile '{name}' uses {mode.upper()} which is trivially crackable.",
                recommendation="Upgrade to WPA2-PSK or WPA3-SAE immediately.",
                profile=name,
            ))

        # --- WPA1 only (no WPA2/WPA3) ---
        auth_list = [a.strip() for a in auth_types.split(",") if a.strip()]
        has_wpa2 = any(a in WPA2_ONLY_MODES | WPA3_MODES for a in auth_list)
        has_wpa1_only = any(a in {"wpa-psk", "wpa-eap"} for a in auth_list) and not has_wpa2

        if has_wpa1_only:
            result.add(Finding(
                severity=Severity.HIGH,
                title="WPA1-only authentication",
                description=f"Profile '{name}' uses WPA1 which is vulnerable to TKIP attacks.",
                recommendation="Migrate to WPA2-PSK (AES) or WPA3-SAE.",
                profile=name,
            ))

        # --- TKIP cipher ---
        cipher_list = [c.strip() for c in (unicast_ciphers + "," + group_ciphers).split(",") if c.strip()]
        if "tkip" in cipher_list:
            result.add(Finding(
                severity=Severity.HIGH,
                title="TKIP cipher enabled",
                description=f"Profile '{name}' allows TKIP which is vulnerable to TKIP MIC attacks.",
                recommendation="Set unicast and group ciphers to AES-CCM (CCMP) only.",
                profile=name,
            ))

        # --- No CCMP/AES ---
        if "aes-ccm" not in cipher_list and "ccmp" not in cipher_list:
            result.add(Finding(
                severity=Severity.HIGH,
                title="AES-CCM (CCMP) cipher not enabled",
                description=f"Profile '{name}' does not use AES-CCM which is required for strong WPA2.",
                recommendation="Enable AES-CCM as the unicast and group cipher.",
                profile=name,
            ))

        # --- Management Frame Protection ---
        if mfp == "disabled":
            severity = Severity.MEDIUM
            if any(a in WPA3_MODES for a in auth_list):
                severity = Severity.HIGH  # MFP is mandatory for WPA3
            result.add(Finding(
                severity=severity,
                title="Management Frame Protection (802.11w) disabled",
                description=(
                    f"Profile '{name}' has MFP disabled. This leaves management frames unprotected, "
                    "enabling deauthentication attacks."
                ),
                recommendation="Set management-protection to 'allowed' (WPA2) or 'required' (WPA3).",
                profile=name,
            ))
        elif mfp == "allowed" and any(a in WPA3_MODES for a in auth_list):
            result.add(Finding(
                severity=Severity.MEDIUM,
                title="MFP only 'allowed', not 'required' on WPA3 profile",
                description=f"Profile '{name}' uses WPA3 but MFP is not enforced.",
                recommendation="Set management-protection to 'required' for WPA3.",
                profile=name,
            ))

        # --- Weak PSK ---
        for key_label, key_value in [("wpa-pre-shared-key", wpa_pre_shared_key), ("wpa2-pre-shared-key", wpa2_pre_shared_key)]:
            if key_value:
                if len(key_value) < 12:
                    result.add(Finding(
                        severity=Severity.HIGH,
                        title="Weak pre-shared key (too short)",
                        description=f"Profile '{name}' {key_label} is under 12 characters.",
                        recommendation="Use a passphrase of at least 20 random characters.",
                        profile=name,
                    ))
                elif len(key_value) < 20:
                    result.add(Finding(
                        severity=Severity.MEDIUM,
                        title="Pre-shared key could be stronger",
                        description=f"Profile '{name}' {key_label} is under 20 characters.",
                        recommendation="Use a passphrase of at least 20 random characters.",
                        profile=name,
                    ))

        # --- Default/common PSK ---
        common_keys = {"admin", "password", "12345678", "mikrotik", "routeros", ""}
        if wpa2_pre_shared_key.lower() in common_keys or wpa_pre_shared_key.lower() in common_keys:
            result.add(Finding(
                severity=Severity.CRITICAL,
                title="Default or empty pre-shared key",
                description=f"Profile '{name}' uses a default or empty passphrase.",
                recommendation="Set a unique, strong passphrase immediately.",
                profile=name,
            ))


# ---------------------------------------------------------------------------
# Interface checks
# ---------------------------------------------------------------------------

def check_interfaces(interfaces: list[dict], result: ScanResult):
    for iface in interfaces:
        name = iface.get("name", "unknown")
        disabled = iface.get("disabled", "false")
        hide_ssid = iface.get("hide-ssid", "false")
        mac_address_mode = iface.get("mac-address", "")
        band = iface.get("band", "")
        ssid = iface.get("ssid", "")

        if disabled == "true":
            continue

        # --- Default SSID ---
        if ssid.lower().startswith("mikrotik") or ssid == "":
            result.add(Finding(
                severity=Severity.MEDIUM,
                title="Default or empty SSID",
                description=f"Interface '{name}' uses SSID '{ssid}' which reveals the router vendor.",
                recommendation="Change SSID to a non-identifying name.",
                interface=name,
            ))

        # --- SSID broadcast vs hidden ---
        if hide_ssid == "true":
            result.add(Finding(
                severity=Severity.INFO,
                title="SSID is hidden",
                description=(
                    f"Interface '{name}' hides the SSID. This provides minimal security "
                    "and can cause connectivity issues."
                ),
                recommendation="Hidden SSIDs are easily discovered by passive scanning. Rely on strong encryption instead.",
                interface=name,
            ))

        # --- 2.4 GHz only band (no 5 GHz) ---
        if "2ghz" in band and "5ghz" not in band:
            result.add(Finding(
                severity=Severity.INFO,
                title="2.4 GHz only band",
                description=f"Interface '{name}' operates only on 2.4 GHz which is more congested and has longer range (larger attack surface).",
                recommendation="Consider enabling 5 GHz where possible to reduce exposure.",
                interface=name,
            ))


# ---------------------------------------------------------------------------
# WPA3 capability check
# ---------------------------------------------------------------------------

def _parse_routeros_major(version_str: str) -> int:
    """Extract major version number from a RouterOS version string like '7.14.2'."""
    try:
        return int(version_str.split(".")[0])
    except (ValueError, IndexError):
        return 0


def check_wpa3(system_info: dict, profiles: list[dict], result: ScanResult):
    version_str = str(system_info.get("version", "") or "")
    major = _parse_routeros_major(version_str)
    result.routeros_version = version_str
    result.wpa3_capable = major >= 7

    if not result.wpa3_capable:
        result.add(Finding(
            severity=Severity.MEDIUM,
            title="RouterOS version does not support WPA3",
            description=(
                f"Your RouterOS version ({version_str or 'unknown'}) is below 7.0. "
                "WPA3 (SAE) requires RouterOS 7.x or higher."
            ),
            recommendation=(
                "Upgrade RouterOS to version 7.x to gain WPA3 support. "
                "Until then, ensure WPA2 is hardened: AES-only cipher, strong PSK, MFP enabled."
            ),
        ))
        return

    # RouterOS 7+ — check if WPA3 is actually used on any profile
    for profile in profiles:
        name = profile.get("name", "unknown")
        auth_types = str(profile.get("authentication-types", "") or "")
        auth_list = [a.strip() for a in auth_types.split(",") if a.strip()]
        mode = profile.get("mode", "none")

        if mode == "none":
            continue

        has_wpa3 = any(a in WPA3_MODES for a in auth_list)
        has_wpa2 = any(a in WPA2_ONLY_MODES for a in auth_list)

        if not has_wpa3 and has_wpa2:
            result.add(Finding(
                severity=Severity.MEDIUM,
                title="WPA3 available but not enabled",
                description=(
                    f"Profile '{name}' uses WPA2 only. Your RouterOS {version_str} supports WPA3 (SAE), "
                    "which replaces the vulnerable 4-way handshake with SAE, eliminating offline dictionary attacks."
                ),
                recommendation=(
                    "Add 'wpa3-psk' to Authentication Types alongside 'wpa2-psk' for a "
                    "WPA2/WPA3 transition mode, or switch fully to WPA3 if all your devices support it."
                ),
                profile=name,
            ))
        elif has_wpa3:
            # WPA3 is on — verify SAE-specific requirements
            mfp = str(profile.get("management-protection", "disabled") or "disabled")
            if mfp != "required":
                result.add(Finding(
                    severity=Severity.HIGH,
                    title="WPA3 profile: MFP must be 'required'",
                    description=(
                        f"Profile '{name}' has WPA3 enabled but management-protection is '{mfp}'. "
                        "The WPA3 spec mandates MFP=required — without it the profile degrades to WPA2 behaviour."
                    ),
                    recommendation="Set management-protection to 'required' on all WPA3 profiles.",
                    profile=name,
                ))

            # Check for SAE-only vs transition mode
            has_wpa1 = any(a in {"wpa-psk", "wpa-eap"} for a in auth_list)
            if has_wpa1:
                result.add(Finding(
                    severity=Severity.MEDIUM,
                    title="WPA3 profile also allows WPA1 — downgrade risk",
                    description=(
                        f"Profile '{name}' has both WPA3 and WPA1 enabled. "
                        "Attackers can force clients to connect via WPA1."
                    ),
                    recommendation="Remove wpa-psk / wpa-eap from Authentication Types.",
                    profile=name,
                ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_scan(interfaces: list[dict], security_profiles: list[dict], system_info: dict | None = None) -> ScanResult:
    result = ScanResult(
        interfaces=interfaces,
        security_profiles=security_profiles,
    )
    check_security_profiles(security_profiles, result)
    check_interfaces(interfaces, result)
    check_wpa3(system_info or {}, security_profiles, result)
    return result
