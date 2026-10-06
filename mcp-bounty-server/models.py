"""Unified data models for bug bounty platform integration."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:
    import yaml  # type: ignore[import-not-found]

    _HAS_YAML = True
except ImportError:  # pragma: no cover - pyyaml is a declared dep; fallback is defensive.
    _HAS_YAML = False


class Platform(Enum):
    BUGBASE = "bugbase"
    BUGCROWD = "bugcrowd"
    BUGRAP = "bugrap"
    CANTINA = "cantina"
    CODE4RENA = "code4rena"
    COMPASS = "compass"
    GOBUGFREE = "gobugfree"
    HACKENPROOF = "hackenproof"
    HACKERONE = "hackerone"
    IMMUNEFI = "immunefi"
    INTIGRITI = "intigriti"
    ISSUEHUNT = "issuehunt"
    PATCHDAY = "patchday"
    REMEDY = "remedy"
    STANDOFF365 = "standoff365"
    YESWEHACK = "yeswehack"


class AssetType(Enum):
    URL = "url"
    WILDCARD = "wildcard"
    IP_RANGE = "ip_range"
    MOBILE_APP = "mobile_app"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"
    SMART_CONTRACT = "smart_contract"
    OTHER = "other"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"
    NONE = "none"


@dataclass
class ScopeAsset:
    asset: str
    asset_type: AssetType
    eligible: bool = True
    max_severity: Optional[Severity] = None
    notes: str = ""


@dataclass
class BountyRange:
    severity: Severity
    min_amount: Optional[float] = None
    max_amount: Optional[float] = None
    currency: str = "USD"


@dataclass
class ProgramScope:
    platform: Platform
    program_handle: str
    program_name: str
    program_url: str
    in_scope: list[ScopeAsset] = field(default_factory=list)
    out_of_scope: list[ScopeAsset] = field(default_factory=list)
    bounty_ranges: list[BountyRange] = field(default_factory=list)
    response_targets: dict[str, str] = field(default_factory=dict)
    last_updated: str = ""


@dataclass
class ProgramPolicy:
    platform: Platform
    program_handle: str
    policy_text: str
    safe_harbor: bool = False
    disclosure_policy: str = ""
    testing_restrictions: list[str] = field(default_factory=list)
    special_instructions: list[str] = field(default_factory=list)


@dataclass
class HacktivityEntry:
    report_id: str
    title: str
    severity: Severity
    state: str  # resolved, disclosed, informative, duplicate, etc.
    bounty_amount: Optional[float] = None
    disclosed_at: str = ""
    vulnerability_type: str = ""
    asset: str = ""
    summary: str = ""
    platform: Platform = Platform.HACKERONE


@dataclass
class ProgramInfo:
    scope: Optional[ProgramScope] = None
    policy: Optional[ProgramPolicy] = None
    hacktivity: list[HacktivityEntry] = field(default_factory=list)


def _yaml_quote(value: str) -> str:
    """Quote arbitrary text as a YAML double-quoted scalar.

    Prefer pyyaml's serializer (handles every C0 control, unicode, and every
    YAML-reserved indicator correctly). Falls back to a conservative hand
    roll only if pyyaml is unavailable — we still escape the common hostile
    characters (quotes, backslashes, and every C0/C1 control including CR/LF
    and the null byte) so malicious asset names cannot smuggle YAML syntax.
    """
    if _HAS_YAML:
        # default_style='"' forces a double-quoted scalar; default_flow_style=True
        # keeps it on one line. strip the trailing newline pyyaml appends.
        return yaml.dump(value, default_style='"', default_flow_style=True, allow_unicode=True).rstrip("\n")
    # Fallback: escape backslash/quote first, then every C0 (0x00-0x1F), DEL,
    # and the C1 range (0x80-0x9F) as \xNN. YAML double-quoted scalars accept
    # \x escapes per the 1.2 spec.
    out = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            out.append(f"\\x{code:02X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def scope_to_txt(scope: ProgramScope) -> str:
    """Convert ProgramScope to .scope.txt format."""
    lines = [
        f"# {scope.program_name}",
        f"# Platform: {scope.platform.value}",
        f"# URL: {scope.program_url}",
        f"# Last updated: {scope.last_updated}",
        "",
        "# In Scope",
    ]
    for asset in scope.in_scope:
        note = f"  # {asset.notes}" if asset.notes else ""
        lines.append(f"{asset.asset}{note}")

    lines.extend(["", "# Out of Scope"])
    for asset in scope.out_of_scope:
        note = f"  # {asset.notes}" if asset.notes else ""
        lines.append(f"{asset.asset}{note}")

    return "\n".join(lines) + "\n"


def scope_to_yaml(scope: ProgramScope) -> str:
    """Convert ProgramScope to scope.yaml format."""
    lines = [
        f"program: {_yaml_quote(scope.program_name)}",
        f"platform: {scope.platform.value}",
        f"url: {_yaml_quote(scope.program_url)}",
        f"last_updated: {_yaml_quote(scope.last_updated)}",
        "",
        "in_scope:",
    ]
    for asset in scope.in_scope:
        lines.append(f"  - asset: {_yaml_quote(asset.asset)}")
        lines.append(f"    type: {asset.asset_type.value}")
        lines.append(f"    eligible: {str(asset.eligible).lower()}")
        if asset.max_severity:
            lines.append(f"    max_severity: {asset.max_severity.value}")
        if asset.notes:
            lines.append(f"    notes: {_yaml_quote(asset.notes)}")

    lines.extend(["", "out_of_scope:"])
    for asset in scope.out_of_scope:
        lines.append(f"  - asset: {_yaml_quote(asset.asset)}")
        lines.append(f"    type: {asset.asset_type.value}")
        if asset.notes:
            lines.append(f"    reason: {_yaml_quote(asset.notes)}")

    if scope.bounty_ranges:
        lines.extend(["", "bounty_range:"])
        for br in scope.bounty_ranges:
            # Use `is not None` (not truthiness) so $0 (free-tier / VDP) renders
            # as "$0" instead of "?". Matches scope_to_markdown below.
            lo = f"${int(br.min_amount)}" if br.min_amount is not None else "?"
            hi = f"${int(br.max_amount)}" if br.max_amount is not None else "?"
            lines.append(f'  {br.severity.value}: "{lo}-{hi}"')
    else:
        lines.extend([
            "",
            "# Bounty table: check the program page for official tier ranges",
            f"# {scope.program_url}",
            "# Actual payout stats from hacktivity are in hacktivity.md",
        ])

    return "\n".join(lines) + "\n"


def scope_to_markdown(scope: ProgramScope) -> str:
    """Convert ProgramScope to human-readable scope.md format."""
    lines = [
        f"# Scope: {scope.program_name}",
        "",
        f"- Platform: `{scope.platform.value}`",
        f"- Program URL: {scope.program_url}",
        f"- Last updated: {scope.last_updated or 'unknown'}",
        "",
        "## In-Scope Assets",
    ]
    if scope.in_scope:
        for asset in scope.in_scope:
            details = [f"type `{asset.asset_type.value}`"]
            if asset.max_severity:
                details.append(f"max severity `{asset.max_severity.value}`")
            details.append(f"bounty eligible `{str(asset.eligible).lower()}`")
            lines.append(f"- `{asset.asset}` ({', '.join(details)})")
            if asset.notes:
                lines.append(f"  - Notes: {asset.notes}")
    else:
        lines.append("- (none returned by platform API)")

    lines.extend(["", "## Out-of-Scope Assets"])
    if scope.out_of_scope:
        for asset in scope.out_of_scope:
            lines.append(f"- `{asset.asset}` (type `{asset.asset_type.value}`)")
            if asset.notes:
                lines.append(f"  - Reason: {asset.notes}")
    else:
        lines.append("- (none returned by platform API)")

    if scope.bounty_ranges:
        lines.extend(["", "## Bounty Ranges"])
        for br in scope.bounty_ranges:
            lo = f"${int(br.min_amount):,}" if br.min_amount is not None else "?"
            hi = f"${int(br.max_amount):,}" if br.max_amount is not None else "?"
            lines.append(f"- `{br.severity.value}`: {lo} - {hi} {br.currency}")

    if scope.response_targets:
        lines.extend(["", "## Program Metadata"])
        for key, value in scope.response_targets.items():
            lines.append(f"- `{key}`: {value}")

    return "\n".join(lines) + "\n"


def hacktivity_to_brain(entries: list[HacktivityEntry], program_name: str) -> str:
    """Convert hacktivity to brain-compatible markdown with payout statistics."""
    lines = [
        f"# Hacktivity — {program_name}",
        f"Total disclosed reports: {len(entries)}",
        "",
    ]

    # Compute actual payout statistics by severity
    payouts_by_sev: dict[str, list[float]] = {}
    for e in entries:
        if e.bounty_amount and e.bounty_amount > 0:
            sev = e.severity.value
            payouts_by_sev.setdefault(sev, []).append(e.bounty_amount)

    if payouts_by_sev:
        lines.extend(["## Actual Payout Statistics (from disclosed reports)", ""])
        lines.append("NOTE: These are real payouts from hacktivity, NOT the program's bounty table.")
        lines.append("Check the program page for the official bounty table with tier ranges.")
        lines.append("")
        sev_order = ["critical", "high", "medium", "low", "informational"]
        for sev in sev_order:
            amounts = payouts_by_sev.get(sev, [])
            if amounts:
                amounts.sort()
                avg = sum(amounts) / len(amounts)
                median = amounts[len(amounts) // 2]
                lines.append(
                    f"- {sev.upper()}: {len(amounts)} payouts, "
                    f"range ${int(min(amounts)):,}-${int(max(amounts)):,}, "
                    f"avg ${int(avg):,}, median ${int(median):,}"
                )
        lines.append("")

    # Vulnerability type frequency
    lines.extend(["## Previously Reported Vulnerability Types", ""])
    type_counts: dict[str, int] = {}
    for e in entries:
        vtype = e.vulnerability_type or "Unknown"
        type_counts[vtype] = type_counts.get(vtype, 0) + 1

    for vtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        lines.append(f"- {vtype}: {count} reports")

    # Recent reports
    lines.extend(["", "## Recent Disclosed Reports", ""])
    for e in entries[:30]:
        bounty = f" (${int(e.bounty_amount):,})" if e.bounty_amount else ""
        lines.append(
            f"- [{e.severity.value.upper()}]{bounty} {e.title} — {e.asset} ({e.state})"
        )

    return "\n".join(lines) + "\n"
