"""HackerOne API provider.

Two endpoints are used:

1. REST Hacker API (authenticated) — https://api.hackerone.com/v1
   Used for structured scopes, which are well-documented and stable.
     GET /v1/hackers/programs/{handle}                    → program info
     GET /v1/hackers/programs/{handle}/structured_scopes  → in/out-of-scope

2. Website GraphQL API (anon + CSRF) — https://hackerone.com/graphql
   Used for policy text and program-filtered hacktivity, because:
   - The REST `policy` field is empty for programs using structured
     policy sections (seen on 23andme_bbp, braze_inc, others).
   - The REST `filter[program][]=handle` filter no longer narrows
     hacktivity results to that program — it returns global hacktivity.
   - The website SPA uses these GraphQL queries itself, so they are
     stable and work without API credentials.
"""

import http.cookiejar
import json
import re
import sys
from base64 import b64encode
from typing import Optional
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import (
    HTTPCookieProcessor,
    Request,
    build_opener,
    urlopen,
)

from models import (
    AssetType, BountyRange, HacktivityEntry, Platform, ProgramPolicy,
    ProgramScope, ScopeAsset, Severity,
)
from providers.base import PlatformProvider

API_BASE = "https://api.hackerone.com/v1"
GRAPHQL_URL = "https://hackerone.com/graphql"
# The root homepage / is a static marketing page without a CSRF token.
# /opportunities/all is a stable Rails-rendered page that always emits one.
CSRF_SEED_URL = "https://hackerone.com/opportunities/all"
REFERER_URL = "https://hackerone.com/"
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)

ASSET_TYPE_MAP = {
    "URL": AssetType.URL,
    "WILDCARD": AssetType.WILDCARD,
    "DOMAIN": AssetType.URL,
    "IP_ADDRESS": AssetType.IP_RANGE,
    "CIDR": AssetType.IP_RANGE,
    "APPLE_STORE_APP_ID": AssetType.MOBILE_APP,
    "GOOGLE_PLAY_APP_ID": AssetType.MOBILE_APP,
    "TESTFLIGHT": AssetType.MOBILE_APP,
    "OTHER_APK": AssetType.MOBILE_APP,
    "WINDOWS_APP_STORE_APP_ID": AssetType.MOBILE_APP,
    "SOURCE_CODE": AssetType.SOURCE_CODE,
    "DOWNLOADABLE_EXECUTABLES": AssetType.OTHER,
    "HARDWARE": AssetType.HARDWARE,
    "SMART_CONTRACT": AssetType.SMART_CONTRACT,
    "OTHER": AssetType.OTHER,
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.NONE,
}


POLICY_QUERY = """
query Team($handle: String!) {
  team(handle: $handle) {
    handle
    name
    policy
  }
}
""".strip()


HACKTIVITY_QUERY = """
query HacktivitySearch(
  $queryString: String!
  $from: Int
  $size: Int
  $sort: SortInput!
) {
  search(
    index: CompleteHacktivityReportIndex
    query_string: $queryString
    from: $from
    size: $size
    sort: $sort
  ) {
    total_count
    nodes {
      __typename
      ... on HacktivityDocument {
        id
        _id
        severity_rating
        total_awarded_amount
        disclosed
        submitted_at
        latest_disclosable_activity_at
        cve_ids
        cwe
        report {
          databaseId: _id
          title
          substate
          url
          disclosed_at
        }
        team {
          handle
          name
        }
      }
    }
  }
}
""".strip()


class HackerOneProvider(PlatformProvider):

    platform_name = "HackerOne"
    platform_id = "hackerone"

    def __init__(self, api_username: Optional[str] = None, api_token: Optional[str] = None):
        super().__init__(api_key=api_token)
        self.api_username = api_username
        self.api_token = api_token
        self._graphql_opener = None
        self._csrf_token: Optional[str] = None

    @property
    def is_configured(self) -> bool:
        return bool(self.api_username and self.api_token)

    def _auth_header(self) -> str:
        creds = b64encode(f"{self.api_username}:{self.api_token}".encode()).decode()
        return f"Basic {creds}"

    def _get(self, path: str) -> dict:
        """Make authenticated GET request to HackerOne REST API."""
        url = f"{API_BASE}{path}"
        req = Request(url, headers={
            "Authorization": self._auth_header(),
            "Accept": "application/json",
        })
        try:
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            if e.code == 401:
                raise PermissionError("HackerOne: invalid credentials. Check HACKERONE_USERNAME and HACKERONE_TOKEN.")
            elif e.code == 403:
                raise PermissionError("HackerOne: forbidden. Your API token may lack permissions for this program.")
            elif e.code == 404:
                return {}
            raise

    def _get_paginated(self, path: str, max_pages: int = 10) -> list[dict]:
        """Fetch all pages from a paginated REST endpoint."""
        all_items = []
        current_path = path
        for _ in range(max_pages):
            data = self._get(current_path)
            items = data.get("data", [])
            if not items:
                break
            all_items.extend(items)
            next_url = data.get("links", {}).get("next")
            if not next_url:
                break
            if next_url.startswith("http"):
                current_path = next_url.replace(API_BASE, "")
            else:
                current_path = next_url
        return all_items

    # ------------------------------------------------------------------
    # Website GraphQL (anon session + CSRF token)
    # ------------------------------------------------------------------

    def _ensure_graphql_session(self) -> None:
        """Seed cookies + CSRF token for the website GraphQL endpoint."""
        if self._graphql_opener is not None and self._csrf_token:
            return

        jar = http.cookiejar.CookieJar()
        opener = build_opener(HTTPCookieProcessor(jar))
        req = Request(CSRF_SEED_URL, headers={
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml",
        })
        with opener.open(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="replace")

        match = re.search(
            r'<meta\s+name="csrf-token"\s+content="([^"]+)"', html
        )
        if not match:
            raise RuntimeError(
                f"HackerOne GraphQL: could not extract CSRF token from "
                f"{CSRF_SEED_URL}"
            )

        self._graphql_opener = opener
        self._csrf_token = match.group(1)

    def _graphql(
        self, query: str, variables: dict, _retry: bool = True
    ) -> dict:
        """Execute a GraphQL query against hackerone.com/graphql."""
        self._ensure_graphql_session()
        body = json.dumps({"query": query, "variables": variables}).encode()
        req = Request(
            GRAPHQL_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-CSRF-Token": self._csrf_token or "",
                "User-Agent": BROWSER_UA,
                "Referer": REFERER_URL,
            },
            method="POST",
        )
        try:
            with self._graphql_opener.open(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            # CSRF / session expired — refresh once and retry
            if e.code in (401, 403, 422) and _retry:
                self._graphql_opener = None
                self._csrf_token = None
                return self._graphql(query, variables, _retry=False)
            raise

    # ------------------------------------------------------------------
    # Public provider API
    # ------------------------------------------------------------------

    async def get_scope(self, program_handle: str) -> Optional[ProgramScope]:
        prog_data = self._get(f"/hackers/programs/{quote(program_handle)}")
        if not prog_data:
            return None
        prog_attrs = prog_data.get("data", {}).get("attributes", {})

        scope_items = self._get_paginated(
            f"/hackers/programs/{quote(program_handle)}/structured_scopes?page%5Bsize%5D=100"
        )

        in_scope = []
        out_of_scope = []
        for item in scope_items:
            attrs = item.get("attributes", {})
            asset = ScopeAsset(
                asset=attrs.get("asset_identifier", ""),
                asset_type=ASSET_TYPE_MAP.get(attrs.get("asset_type", "OTHER"), AssetType.OTHER),
                eligible=attrs.get("eligible_for_bounty", False),
                max_severity=SEVERITY_MAP.get(attrs.get("max_severity", ""), None),
                notes=attrs.get("instruction", ""),
            )
            if attrs.get("eligible_for_submission", True):
                in_scope.append(asset)
            else:
                out_of_scope.append(asset)

        return ProgramScope(
            platform=Platform.HACKERONE,
            program_handle=program_handle,
            program_name=prog_attrs.get("name", program_handle),
            program_url=f"https://hackerone.com/{program_handle}",
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            last_updated=prog_attrs.get("updated_at", ""),
        )

    async def get_policy(self, program_handle: str) -> Optional[ProgramPolicy]:
        # Authenticated REST call — gives us submission_state + safe_harbor
        data = self._get(f"/hackers/programs/{quote(program_handle)}")
        if not data:
            return None

        attrs = data.get("data", {}).get("attributes", {})
        policy_text = (attrs.get("policy") or "").strip()

        # REST often returns empty policy for programs using structured
        # policy sections. Use GraphQL for the actual policy text.
        if not policy_text:
            policy_text = self._fetch_policy_via_graphql(program_handle)

        restrictions = []
        submission_state = attrs.get("submission_state")
        if submission_state and submission_state != "open":
            restrictions.append(f"Submission state: {submission_state}")

        return ProgramPolicy(
            platform=Platform.HACKERONE,
            program_handle=program_handle,
            policy_text=policy_text,
            safe_harbor=attrs.get("gold_standard_safe_harbor", False),
            testing_restrictions=restrictions,
        )

    def _fetch_policy_via_graphql(self, program_handle: str) -> str:
        try:
            result = self._graphql(POLICY_QUERY, {"handle": program_handle})
        except Exception as exc:
            print(
                f"HackerOne GraphQL policy fetch failed for "
                f"{program_handle}: {exc}",
                file=sys.stderr,
            )
            return ""

        errors = result.get("errors")
        if errors:
            print(
                f"HackerOne GraphQL policy errors for {program_handle}: "
                f"{errors}",
                file=sys.stderr,
            )
            return ""

        team = (result.get("data") or {}).get("team") or {}
        return (team.get("policy") or "").strip()

    async def search_hacktivity(
        self, program_handle: str, query: str = "", limit: int = 50
    ) -> list[HacktivityEntry]:
        # The REST `filter[program][]` filter no longer scopes to a
        # single program — it returns global hacktivity. Use GraphQL
        # with a Lucene-style `team_handle:` filter instead.
        #
        # Fetch disclosed reports first (best for dupcheck and vuln type
        # stats), then top up with undisclosed-but-bountied entries
        # (useful for payout statistics). Programs that never publicly
        # disclose (e.g. 23andme_bbp) still get populated from the
        # undisclosed pass.
        size = min(max(limit, 1), 100)

        entries = self._run_hacktivity_search(
            program_handle, query, size, disclosed_only=True
        )

        if len(entries) < limit:
            extra = self._run_hacktivity_search(
                program_handle, query, size, disclosed_only=False
            )
            seen_ids = {e.report_id for e in entries if e.report_id}
            for e in extra:
                if e.report_id and e.report_id in seen_ids:
                    continue
                # Skip undisclosed noise (no bounty, no severity)
                if e.bounty_amount is None and e.severity == Severity.NONE:
                    continue
                entries.append(e)
                if len(entries) >= limit:
                    break

        return entries[:limit]

    def _run_hacktivity_search(
        self,
        program_handle: str,
        query: str,
        size: int,
        disclosed_only: bool,
    ) -> list[HacktivityEntry]:
        filters = [f"team_handle:{program_handle}"]
        if disclosed_only:
            filters.append("disclosed:true")
        if query:
            filters.append(f"({query})")
        variables = {
            "queryString": " AND ".join(filters),
            "from": 0,
            "size": size,
            "sort": {
                "field": "latest_disclosable_activity_at",
                "direction": "DESC",
            },
        }

        try:
            result = self._graphql(HACKTIVITY_QUERY, variables)
        except Exception as exc:
            print(
                f"HackerOne GraphQL hacktivity fetch failed for "
                f"{program_handle}: {exc}",
                file=sys.stderr,
            )
            return []

        errors = result.get("errors")
        if errors:
            print(
                f"HackerOne GraphQL hacktivity errors for {program_handle}: "
                f"{errors}",
                file=sys.stderr,
            )
            return []

        nodes = (
            ((result.get("data") or {}).get("search") or {}).get("nodes")
            or []
        )
        return [
            self._hacktivity_node_to_entry(n)
            for n in nodes
            if n.get("__typename") == "HacktivityDocument"
        ]

    @staticmethod
    def _hacktivity_node_to_entry(node: dict) -> HacktivityEntry:
        report = node.get("report") or {}
        severity_raw = (node.get("severity_rating") or "none").lower()
        severity = SEVERITY_MAP.get(severity_raw, Severity.NONE)

        # HacktivityDocument exposes cwe/cve_ids but not a human weakness
        # name. Use whichever is present to tag the vuln type.
        cwe = node.get("cwe")
        cves = node.get("cve_ids") or []
        vuln_type_parts: list[str] = []
        if cwe:
            vuln_type_parts.append(str(cwe))
        if isinstance(cves, list) and cves:
            vuln_type_parts.append(", ".join(str(c) for c in cves))
        vuln_type = " / ".join(vuln_type_parts)

        title = report.get("title") or ""
        if not title:
            # Private/undisclosed entries still count for payout stats
            title = "[Undisclosed]"

        report_id = str(
            report.get("databaseId")
            or node.get("_id")
            or node.get("id")
            or ""
        )

        return HacktivityEntry(
            report_id=report_id,
            title=title,
            severity=severity,
            state=report.get("substate") or (
                "disclosed" if node.get("disclosed") else "private"
            ),
            bounty_amount=node.get("total_awarded_amount"),
            disclosed_at=(
                report.get("disclosed_at")
                or node.get("latest_disclosable_activity_at")
                or ""
            ),
            vulnerability_type=vuln_type,
            asset="",
            summary=title,
            platform=Platform.HACKERONE,
        )
