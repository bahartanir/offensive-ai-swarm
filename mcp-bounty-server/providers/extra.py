"""Additional bug bounty platform providers.

Intigriti: https://app.intigriti.com/api/
Immunefi: https://immunefi.com (web3-focused, public program data)
YesWeHack: https://api.yeswehack.com/
"""

import json
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import quote

from models import (
    AssetType, BountyRange, HacktivityEntry, Platform, ProgramPolicy,
    ProgramScope, ScopeAsset, Severity,
)
from providers.base import PlatformProvider

SEVERITY_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "none": Severity.NONE, "informational": Severity.INFO}


def _fetch_json(url: str, headers: dict, timeout: int = 30) -> dict:
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        if e.code in (401, 403):
            raise PermissionError(f"Auth failed ({e.code}) for {url}")
        elif e.code == 404:
            return {}
        raise


def _fetch_json_optional(url: str, headers: dict, timeout: int = 30) -> Optional[dict]:
    """Like _fetch_json but returns None on any auth/network failure.

    Used for the SPA cookie-auth path where 401/403 should fall back gracefully
    to the PAT-only researcher API rather than raising.
    """
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (HTTPError, OSError):
        return None


# --- Intigriti ---

class IntigritiProvider(PlatformProvider):
    """Intigriti researcher API client.

    Two data sources:

    1. Public researcher API at `api.intigriti.com/external/researcher/v1` —
       authenticates with a Personal Access Token. Read-only, exposes 6 GET
       endpoints. Returns the canonical structured scope (domains.content[])
       and basic rules-of-engagement, but NOT the rich program description,
       scope intro, OOS rules list, severity assessments, FAQs, or bounty
       tables.

    2. SPA-private API at `app.intigriti.com/api/core/researcher/programs` —
       authenticates with the SPA session cookie (`__Host-Intigriti.Web.
       Researcher`). This is what the web UI uses. Returns ~50KB of rich
       payload including all the human-readable program copy.

    Strategy: PAT path is mandatory and gives us a working baseline. The SPA
    cookie path is opportunistic — if `INTIGRITI_SPA_COOKIE` is set, we
    enrich scope (bounty ranges) and policy (intro + OOS rules + severity +
    FAQ) with the SPA data. On 401 (cookie expired) we silently fall back
    to PAT-only data.
    """

    platform_name = "Intigriti"
    platform_id = "intigriti"
    API_BASE = "https://api.intigriti.com/external/researcher/v1"
    SPA_BASE = "https://app.intigriti.com/api/core/researcher"
    BASE = API_BASE  # Backwards compat

    # Maps Intigriti `domains.content[].type.value` → unified AssetType. Keys are
    # lowercased and stripped of spaces so "Source code" and "Sourcecode" both hit.
    _ASSET_TYPE_MAP = {
        "url": AssetType.URL,
        "wildcard": AssetType.WILDCARD,
        "ipaddress": AssetType.IP_RANGE,
        "iprange": AssetType.IP_RANGE,
        "android": AssetType.MOBILE_APP,
        "ios": AssetType.MOBILE_APP,
        "device": AssetType.HARDWARE,
        "hardware": AssetType.HARDWARE,
        "sourcecode": AssetType.SOURCE_CODE,
        "other": AssetType.OTHER,
    }

    # CVSS 3.1 base score → severity buckets used by Intigriti bounty tables.
    # Tables list ranges by minScore/maxScore; we map each range to the highest
    # severity it can reach (so 9.0-9.4 lands in CRITICAL not HIGH).
    @staticmethod
    def _cvss_to_severity(min_score: float, max_score: float) -> Severity:
        if max_score >= 9.0:
            return Severity.CRITICAL
        if max_score >= 7.0:
            return Severity.HIGH
        if max_score >= 4.0:
            return Severity.MEDIUM
        if max_score >= 0.1:
            return Severity.LOW
        return Severity.NONE

    def __init__(self, api_key=None, api_secret=None, spa_cookie: Optional[str] = None):
        super().__init__(api_key, api_secret)
        self._handle_to_uuid: dict[str, str] = {}
        self._spa_cache: dict[str, Optional[dict]] = {}
        # Accept either a bare value (just the session cookie) or a full
        # `name=value; name2=value2` cookie header.
        self._spa_cookie = self._normalize_cookie(spa_cookie) if spa_cookie else None

    @staticmethod
    def _normalize_cookie(raw: str) -> str:
        raw = raw.strip()
        if "=" in raw:
            return raw  # User pasted the full Cookie header
        return f"__Host-Intigriti.Web.Researcher={raw}"

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}

    def _spa_headers(self):
        return {
            "Cookie": self._spa_cookie or "",
            "Accept": "application/json",
            # The SPA-private API serves a 403 to default urllib UA; mirror a
            # browser UA so the request looks like the SPA's own fetches.
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Intigriti-MCP/1.0",
        }

    def _get_spa_program(self, uuid: str) -> Optional[dict]:
        """Fetch the SPA-private program payload (rich content). None if the
        cookie isn't set or auth failed."""
        if not self._spa_cookie:
            return None
        if uuid in self._spa_cache:
            return self._spa_cache[uuid]
        data = _fetch_json_optional(f"{self.SPA_BASE}/programs/{uuid}", self._spa_headers())
        self._spa_cache[uuid] = data
        return data

    def _resolve_uuid(self, program_handle: str) -> Optional[str]:
        """Resolve a program handle to its UUID, cached per provider lifetime."""
        if program_handle in self._handle_to_uuid:
            return self._handle_to_uuid[program_handle]
        data = _fetch_json(f"{self.BASE}/programs?limit=500", self._headers())
        for record in data.get("records", []):
            handle = record.get("handle")
            uuid = record.get("id")
            if handle and uuid:
                self._handle_to_uuid[handle] = uuid
        return self._handle_to_uuid.get(program_handle)

    def _map_asset_type(self, type_value: str) -> AssetType:
        return self._ASSET_TYPE_MAP.get(type_value.lower().replace(" ", ""), AssetType.OTHER)

    @staticmethod
    def _latest(versioned: list) -> Optional[dict]:
        """Pick the entry with the highest createdAt from a versioned list.

        SPA payloads expose history as `[{content, createdAt}, ...]`. The web
        UI shows the latest revision; we do the same.
        """
        if not versioned:
            return None
        return max(versioned, key=lambda x: (x or {}).get("createdAt", 0))

    def _bounty_ranges_from_spa(self, spa: dict) -> list[BountyRange]:
        """Extract structured BountyRange entries from the SPA's bountyTables.

        Bounty tables are CVSS-score keyed (minScore/maxScore + minBounty/
        maxBounty). We collapse each row into our severity buckets and keep the
        widest min-max envelope per severity (covers programs that publish
        multiple per-asset-tier tables).
        """
        if not spa or not spa.get("bountyTables"):
            return []
        latest = self._latest(spa["bountyTables"])
        if not latest:
            return []
        content = latest.get("content") or {}
        currency = content.get("currency", "EUR")

        by_sev: dict[Severity, tuple[float, float]] = {}
        for row in content.get("bountyRows", []) or []:
            for rng in row.get("bountyRanges", []) or []:
                sev = self._cvss_to_severity(
                    float(rng.get("minScore", 0.0)),
                    float(rng.get("maxScore", 0.0)),
                )
                lo = float((rng.get("minBounty") or {}).get("value", 0))
                hi = float((rng.get("maxBounty") or {}).get("value", 0))
                cur = by_sev.get(sev)
                if cur is None:
                    by_sev[sev] = (lo, hi)
                else:
                    by_sev[sev] = (min(cur[0], lo), max(cur[1], hi))

        return [
            BountyRange(severity=sev, min_amount=lo, max_amount=hi, currency=currency)
            for sev, (lo, hi) in by_sev.items()
        ]

    async def get_scope(self, program_handle: str) -> Optional[ProgramScope]:
        uuid = self._resolve_uuid(program_handle)
        if not uuid:
            return None
        data = _fetch_json(f"{self.API_BASE}/programs/{uuid}", self._headers())
        if not data:
            return None

        # Intigriti encodes in-scope vs out-of-scope on the SAME domains.content
        # array via the `tier` field. tier.id == 5 / value == "Out Of Scope"
        # marks an asset as explicitly out of scope. Everything else is in scope
        # at some bounty tier (Tier 1/2/3, etc).
        in_scope, out_of_scope = [], []
        for entry in (data.get("domains") or {}).get("content", []):
            type_value = (entry.get("type") or {}).get("value", "")
            tier = entry.get("tier") or {}
            tier_id = tier.get("id")
            tier_value = tier.get("value", "")
            is_oos = tier_id == 5 or tier_value.lower() == "out of scope"

            description = (entry.get("description") or "").strip()
            # For in-scope items the tier label is meaningful (Tier 1/2/3) and
            # belongs in notes. For OOS items the tier label is just "Out Of
            # Scope" — redundant once we've routed it to out_of_scope, so drop it.
            note_parts = [description] if is_oos else [p for p in (tier_value, description) if p]
            asset = ScopeAsset(
                asset=entry.get("endpoint", ""),
                asset_type=self._map_asset_type(type_value),
                eligible=not is_oos,
                notes=" — ".join(p for p in note_parts if p),
            )
            (out_of_scope if is_oos else in_scope).append(asset)

        web_detail = (data.get("webLinks") or {}).get("detail", "")

        # Enrich with bounty ranges from the SPA's bountyTables when available.
        # PAT-only mode leaves bounty_ranges empty (caller's renderer falls
        # back to "see program page for bounty table").
        spa = self._get_spa_program(uuid)
        bounty_ranges = self._bounty_ranges_from_spa(spa) if spa else []

        # Surface "is the program currently active" via response_targets so the
        # rendered scope.md/.yaml includes operational context. Keys are
        # rendered as a Program Metadata section by scope_to_markdown.
        response_targets = {}
        if spa:
            for k, label in (
                ("submissionCount", "Total submissions"),
                ("acceptedSubmissionCount", "Accepted submissions"),
                ("identityCheckedRequired", "Identity check required"),
                ("twoFactorRequired", "2FA required"),
                ("eeaRequired", "EEA-only program"),
                ("companyName", "Company"),
            ):
                if k in spa and spa[k] is not None:
                    response_targets[label] = str(spa[k])

        return ProgramScope(
            platform=Platform.INTIGRITI,
            program_handle=program_handle,
            program_name=data.get("name", program_handle),
            program_url=web_detail or f"https://app.intigriti.com/researcher/program-redirect/{program_handle}",
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            bounty_ranges=bounty_ranges,
            response_targets=response_targets,
            last_updated=str((data.get("domains") or {}).get("createdAt", "")),
        )

    async def get_policy(self, program_handle: str) -> Optional[ProgramPolicy]:
        uuid = self._resolve_uuid(program_handle)
        if not uuid:
            return None
        data = _fetch_json(f"{self.API_BASE}/programs/{uuid}", self._headers())
        if not data:
            return None

        roe_content = ((data.get("rulesOfEngagement") or {}).get("content") or {})
        testing_req = roe_content.get("testingRequirements") or {}

        restrictions = []
        if testing_req.get("intigritiMe"):
            restrictions.append("Must use intigriti.me email/IP for testing")
        if testing_req.get("userAgent"):
            restrictions.append(f"Required User-Agent: {testing_req['userAgent']}")
        if testing_req.get("requestHeader"):
            restrictions.append(f"Required header: {testing_req['requestHeader']}")
        if testing_req.get("automatedTooling") is not None:
            label = {0: "allowed", 1: "restricted", 2: "forbidden"}.get(
                testing_req["automatedTooling"], f"code={testing_req['automatedTooling']}"
            )
            restrictions.append(f"Automated tooling: {label}")

        # Compose policy_text: PAT-only path gives only the generic RoE
        # description (~1KB). When the SPA cookie is wired, we prepend the
        # program description and append the program-specific in-scope intro,
        # OOS rules, severity assessments, and FAQs — that's what shows up on
        # the program page.
        policy_sections: list[str] = []
        spa = self._get_spa_program(uuid)
        if spa:
            blurb = (spa.get("description") or "").strip()
            if blurb:
                policy_sections.append(f"## Description\n\n{blurb}")
            in_scope_md = self._latest_section_text(spa.get("inScopes"))
            if in_scope_md:
                policy_sections.append(f"## In-Scope Rules\n\n{in_scope_md}")
            out_of_scope_md = self._latest_section_text(spa.get("outOfScopes"))
            if out_of_scope_md:
                policy_sections.append(f"## Out-of-Scope Rules\n\n{out_of_scope_md}")
            sev_md = self._latest_section_text(spa.get("severityAssessments"))
            if sev_md:
                policy_sections.append(f"## Severity Assessment\n\n{sev_md}")
            faq_md = self._latest_section_text(spa.get("faqs"))
            if faq_md:
                policy_sections.append(f"## FAQ\n\n{faq_md}")

        # The generic RoE block (~1KB) is shared across many Intigriti
        # programs — keep it at the bottom under its own heading so the
        # program-specific sections lead.
        roe_text = (roe_content.get("description") or "").strip()
        if roe_text:
            policy_sections.append(f"## Rules of Engagement\n\n{roe_text}")

        # If the SPA cookie wasn't available we still want a useful policy_text
        # — fall back to the generic RoE alone (matches pre-cookie behaviour).
        if not policy_sections:
            policy_sections.append(roe_text)

        return ProgramPolicy(
            platform=Platform.INTIGRITI,
            program_handle=program_handle,
            policy_text="\n\n".join(s for s in policy_sections if s),
            safe_harbor=bool(roe_content.get("safeHarbour", False)),  # British spelling in API
            testing_restrictions=restrictions,
        )

    @classmethod
    def _latest_section_text(cls, versioned: Optional[list]) -> str:
        """Return `.content.content` (markdown body) of the latest revision.

        SPA section payloads nest the actual text two levels deep:
        `[{content: {content: "..."}, createdAt: ...}]`. Some entries (notably
        rulesOfEngagements) put a structured dict at the inner key instead of
        a string — we ignore those here since the structured fields are read
        elsewhere.
        """
        if not versioned:
            return ""
        latest = cls._latest(versioned)
        if not latest:
            return ""
        inner = ((latest.get("content") or {}).get("content"))
        return inner.strip() if isinstance(inner, str) else ""

    async def search_hacktivity(self, program_handle: str, query: str = "", limit: int = 50) -> list[HacktivityEntry]:
        # The Intigriti researcher API does not expose disclosed reports for
        # other researchers — submissions are private to the reporter. The
        # public hacktivity feed at app.intigriti.com/researcher/hacktivity is
        # served via the SPA and needs a session cookie, not a PAT. Return
        # empty rather than 404'ing.
        return []


# --- Immunefi (web3 — public program listing, no auth needed for basic data) ---

class ImmunefiProvider(PlatformProvider):
    platform_name = "Immunefi"
    platform_id = "immunefi"

    @property
    def is_configured(self) -> bool:
        return True  # Public API for program data

    async def get_scope(self, program_handle: str) -> Optional[ProgramScope]:
        data = _fetch_json(
            f"https://immunefi.com/api/bounty/{quote(program_handle)}/",
            {"Accept": "application/json"},
        )
        if not data:
            return None

        in_scope = []
        for asset in data.get("assets", []):
            in_scope.append(ScopeAsset(
                asset=asset.get("target", ""),
                asset_type=AssetType.SMART_CONTRACT if "contract" in asset.get("type", "").lower() else AssetType.URL,
                eligible=True,
                notes=asset.get("type", ""),
            ))

        bounty_ranges = []
        for sev, amount in data.get("maximumPayout", {}).items():
            s = SEVERITY_MAP.get(sev.lower())
            if s and amount:
                bounty_ranges.append(
                    __import__("models").BountyRange(severity=s, max_amount=float(str(amount).replace(",", "")))
                )

        return ProgramScope(
            platform=Platform.IMMUNEFI,
            program_handle=program_handle,
            program_name=data.get("project", program_handle),
            program_url=f"https://immunefi.com/bug-bounty/{program_handle}/",
            in_scope=in_scope,
            bounty_ranges=bounty_ranges,
            last_updated=data.get("updatedDate", ""),
        )

    async def get_policy(self, program_handle: str) -> Optional[ProgramPolicy]:
        data = _fetch_json(f"https://immunefi.com/api/bounty/{quote(program_handle)}/", {"Accept": "application/json"})
        if not data:
            return None
        return ProgramPolicy(
            platform=Platform.IMMUNEFI,
            program_handle=program_handle,
            policy_text=data.get("description", ""),
            testing_restrictions=data.get("outOfScope", []) if isinstance(data.get("outOfScope"), list) else [],
        )

    async def search_hacktivity(self, program_handle: str, query: str = "", limit: int = 50) -> list[HacktivityEntry]:
        return []  # Immunefi doesn't publicly expose individual report data


# --- YesWeHack ---
#
# Public programs expose scope, rules, and hacktivity without authentication
# at api.yeswehack.com. Sending a Bearer header with no/invalid token triggers
# 401, so we only attach Authorization when an api_key is actually set. A
# token only becomes necessary for report submission and private programs.


_YWH_GRID_TIERS = [
    ("very_low", "Very low"),
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]
_YWH_GRID_KEYS = [
    ("bounty_low", "Low finding"),
    ("bounty_medium", "Medium finding"),
    ("bounty_high", "High finding"),
    ("bounty_critical", "Critical finding"),
]


def _format_reward_matrix(data: dict) -> str:
    """Render YWH's 2D reward grid (scope tier x finding severity) as Markdown.

    Rows are scope-severity tiers (the `asset_value` on each scope entry);
    columns are finding-severity payouts. Empty (all-null) rows are skipped
    so we don't clutter the output with tiers the program doesn't use.
    """
    rows: list[tuple[str, dict]] = []
    for key, label in _YWH_GRID_TIERS:
        grid = data.get(f"reward_grid_{key}") or {}
        if any(grid.get(k) for k, _ in _YWH_GRID_KEYS):
            rows.append((label, grid))
    if not rows:
        return ""

    header = "| Scope tier \\ finding | " + " | ".join(label for _, label in _YWH_GRID_KEYS) + " |"
    divider = "|" + "|".join(["---"] * (len(_YWH_GRID_KEYS) + 1)) + "|"
    body = []
    for label, grid in rows:
        cells = [f"€{grid[k]:,}" if grid.get(k) else "—" for k, _ in _YWH_GRID_KEYS]
        body.append(f"| {label} | " + " | ".join(cells) + " |")
    return "## Reward matrix (EUR)\n\n" + "\n".join([header, divider] + body)


def _format_systemic_rule(data: dict) -> str:
    """Render YWH's systemic-issue reward grid as Markdown, if enabled."""
    if not data.get("systemic_issue_rule_enabled"):
        return ""
    grid = data.get("systemic_issue_rule_grid") or {}
    if not grid:
        return ""
    lines = [
        "## Systemic issue reward",
        "",
        "Percentage of the base bounty paid when a vulnerability appears across multiple assets:",
        "",
    ]
    for level in sorted(grid):
        lines.append(f"- **{level}**: {grid[level]}%")
    return "\n".join(lines)


class YesWeHackProvider(PlatformProvider):
    platform_name = "YesWeHack"
    platform_id = "yeswehack"

    @property
    def is_configured(self) -> bool:
        # Public program data works without credentials.
        return True

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def get_scope(self, program_handle: str) -> Optional[ProgramScope]:
        data = _fetch_json(
            f"https://api.yeswehack.com/programs/{quote(program_handle)}",
            self._headers(),
        )
        if not data:
            return None

        in_scope = []
        for scope_item in data.get("scopes", []):
            # `scope` holds the target string (URL / regex / app id).
            # `asset_value` holds the max severity tier, not the asset itself.
            # `scope_type` is YWH's internal slug (web-application,
            # mobile-application-ios, etc.); `scope_type_name` is human-readable.
            scope_type = (scope_item.get("scope_type") or "").lower()
            if "mobile" in scope_type:
                asset_type = AssetType.MOBILE_APP
            elif "wildcard" in scope_type:
                asset_type = AssetType.WILDCARD
            elif "source" in scope_type or "code" in scope_type:
                asset_type = AssetType.SOURCE_CODE
            elif "ip" in scope_type:
                asset_type = AssetType.IP_RANGE
            else:
                asset_type = AssetType.URL

            in_scope.append(ScopeAsset(
                asset=scope_item.get("scope", ""),
                asset_type=asset_type,
                eligible=True,
                max_severity=SEVERITY_MAP.get(
                    str(scope_item.get("asset_value", "")).lower()
                ),
                notes=scope_item.get("scope_type_name") or scope_item.get("scope_type", ""),
            ))

        out_of_scope = []
        for entry in data.get("out_of_scope", []):
            # YWH ships out_of_scope as a list of free-form strings (one per
            # line on the public page). We surface each as a non-eligible
            # asset so downstream scope checks have something to compare.
            if isinstance(entry, str):
                out_of_scope.append(ScopeAsset(
                    asset=entry,
                    asset_type=AssetType.OTHER,
                    eligible=False,
                ))
            elif isinstance(entry, dict):
                out_of_scope.append(ScopeAsset(
                    asset=entry.get("asset_value") or entry.get("scope", ""),
                    asset_type=AssetType.OTHER,
                    eligible=False,
                    notes=entry.get("scope_type_name") or entry.get("scope_type", ""),
                ))

        # YWH reward grids are 2D: the per-severity dict is repeated for each
        # scope-severity tier (reward_grid_low/medium/high/critical). Highest
        # payout lives in reward_grid_critical, which represents what a given
        # finding-severity pays on a critical-tier scope asset. We expose that
        # as bounty_ranges (the max hunters can earn) and stash the lower
        # tiers as informational context in response_targets.
        grid_map = {
            "bounty_low": Severity.LOW,
            "bounty_medium": Severity.MEDIUM,
            "bounty_high": Severity.HIGH,
            "bounty_critical": Severity.CRITICAL,
        }
        bounty_ranges = []
        best_grid = (
            data.get("reward_grid_critical")
            or data.get("reward_grid_high")
            or data.get("reward_grid_medium")
            or data.get("reward_grid_low")
            or data.get("reward_grid_default")
            or {}
        )
        for key, sev in grid_map.items():
            amount = best_grid.get(key)
            if amount:
                bounty_ranges.append(BountyRange(
                    severity=sev,
                    max_amount=float(amount),
                    currency="EUR",
                ))

        # Carry operationally-important YWH metadata through response_targets
        # (a free-form dict on ProgramScope). These are strings because the
        # field's contract is str→str; hunters read them from scope.yaml.
        response_targets: dict[str, str] = {}
        if data.get("user_agent"):
            response_targets["required_user_agent"] = data["user_agent"]
        stats = data.get("stats") or {}
        if stats.get("average_first_time_response") is not None:
            response_targets["avg_first_response_days"] = str(stats["average_first_time_response"])
        if stats.get("total_reports") is not None:
            response_targets["total_reports"] = str(stats["total_reports"])
        if stats.get("total_reports_last7_days") is not None:
            response_targets["reports_last_7d"] = str(stats["total_reports_last7_days"])
        if data.get("type"):
            response_targets["program_type"] = str(data["type"])
        if data.get("vpn_active") is not None:
            response_targets["vpn_required"] = "yes" if data["vpn_active"] else "no"

        return ProgramScope(
            platform=Platform.YESWEHACK,
            program_handle=program_handle,
            program_name=data.get("title", program_handle),
            program_url=f"https://yeswehack.com/programs/{program_handle}",
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            bounty_ranges=bounty_ranges,
            response_targets=response_targets,
            last_updated=data.get("updated_at", ""),
        )

    async def get_policy(self, program_handle: str) -> Optional[ProgramPolicy]:
        data = _fetch_json(
            f"https://api.yeswehack.com/programs/{quote(program_handle)}",
            self._headers(),
        )
        if not data:
            return None

        # YWH surfaces several program rules outside the `rules` markdown:
        # - user_agent: every request must include this UA string so the
        #   target can identify legitimate bounty traffic. Missing it can
        #   get the hunter blocked or flagged by WAF/SIEM.
        # - account_access: free-text instructions on how to create a test
        #   account. Without this, auth-testing is impossible.
        # - qualifying_vulnerability / non_qualifying_vulnerability: dedicated
        #   lists that programs curate independently of the rules markdown.
        # - reward grids: 2D severity matrix (finding severity × scope tier).
        # - systemic_issue_rule_grid: payouts for repeated findings across
        #   assets. Relevant for chain-building and dup considerations.
        #
        # We prepend a "Testing setup" block at the top so the required UA
        # and account-access instructions are impossible to miss, then the
        # original rules, then the vuln lists, then the reward matrices.
        parts: list[str] = []

        setup_lines: list[str] = []
        required_ua = data.get("user_agent")
        if required_ua:
            setup_lines.append(
                f"**Required User-Agent**: every request must include "
                f"`User-Agent: {required_ua}`. Failing to set this risks "
                f"being treated as hostile traffic by the target."
            )
        account_access = data.get("account_access")
        if account_access:
            setup_lines.append("**Test account setup**:\n\n" + account_access)
        if data.get("vpn_active"):
            setup_lines.append(
                "**VPN required** for this program. Check vpn_ips in scope metadata."
            )
        if setup_lines:
            parts.append("## Testing setup\n\n" + "\n\n".join(setup_lines))

        base_rules = data.get("rules", "") or data.get("description", "")
        if base_rules:
            parts.append(base_rules)

        qualifying = [str(v) for v in data.get("qualifying_vulnerability", []) if v]
        if qualifying:
            parts.append(
                "## Qualifying vulnerabilities\n\n"
                + "\n".join(f"- {item}" for item in qualifying)
            )

        non_qualifying = [str(v) for v in data.get("non_qualifying_vulnerability", []) if v]
        if non_qualifying:
            parts.append(
                "## Non-qualifying vulnerabilities\n\n"
                + "\n".join(f"- {item}" for item in non_qualifying)
            )

        reward_matrix_md = _format_reward_matrix(data)
        if reward_matrix_md:
            parts.append(reward_matrix_md)

        systemic_md = _format_systemic_rule(data)
        if systemic_md:
            parts.append(systemic_md)

        return ProgramPolicy(
            platform=Platform.YESWEHACK,
            program_handle=program_handle,
            policy_text="\n\n".join(parts),
            testing_restrictions=non_qualifying,
        )

    async def search_hacktivity(self, program_handle: str, query: str = "", limit: int = 50) -> list[HacktivityEntry]:
        # /programs/<slug>/reports requires auth. /hacktivity is public but
        # only exposes hunter + bug_type + status + date — no titles or
        # severity. We surface the CWE name as the title so downstream
        # dup-check / intel still has something to match on.
        data = _fetch_json(
            f"https://api.yeswehack.com/hacktivity?programs[]={quote(program_handle)}&nb_results={limit}",
            self._headers(),
        )
        entries = []
        for it in data.get("items", [])[:limit]:
            report = it.get("report") or {}
            bug_type = report.get("bug_type") or {}
            status = it.get("status") or {}
            state = status.get("workflow_state", "") if isinstance(status, dict) else str(status)
            entries.append(HacktivityEntry(
                report_id=str(report.get("local_id") or ""),
                title=bug_type.get("name") or bug_type.get("short_name", ""),
                severity=SEVERITY_MAP.get(str(report.get("severity", "")).lower(), Severity.NONE),
                state=state,
                platform=Platform.YESWEHACK,
            ))
        return entries


# --- Stub provider for platforms without well-documented APIs ---

class StubProvider(PlatformProvider):
    """Placeholder for platforms whose APIs are undocumented or require scraping."""

    def __init__(self, platform_name_: str, platform_id_: str, base_url: str = "", **kwargs):
        super().__init__(**kwargs)
        self._name = platform_name_
        self._id = platform_id_
        self._base_url = base_url

    @property
    def platform_name(self) -> str:
        return self._name

    @property
    def platform_id(self) -> str:
        return self._id

    async def get_scope(self, program_handle: str) -> Optional[ProgramScope]:
        return None  # Not implemented — add scope manually or contribute an API integration

    async def get_policy(self, program_handle: str) -> Optional[ProgramPolicy]:
        return None

    async def search_hacktivity(self, program_handle: str, query: str = "", limit: int = 50) -> list[HacktivityEntry]:
        return []


# --- Provider registry ---

STUB_PLATFORMS = [
    ("Bugbase", "bugbase", "https://bugbase.in"),
    ("BugRap", "bugrap", "https://bugrap.io"),
    ("Cantina", "cantina", "https://cantina.xyz"),
    ("Code4rena", "code4rena", "https://code4rena.com"),
    ("Compass Security", "compass", "https://compass-security.com"),
    ("GObugfree", "gobugfree", "https://gobugfree.com"),
    ("HackenProof", "hackenproof", "https://hackenproof.com"),
    ("IssueHunt", "issuehunt", "https://issuehunt.io"),
    ("PatchDay", "patchday", "https://patchday.io"),
    ("Remedy", "remedy", "https://remedy.security"),
    ("Standoff365", "standoff365", "https://standoff365.com"),
]
