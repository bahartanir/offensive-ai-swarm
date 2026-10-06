"""Bugcrowd provider — public scraping + optional authenticated session.

Public data (no login needed):
    - Program brief/policy via HTML scraping of /engagements/{handle}
    - Basic statistics via /engagements/{handle}/statistics

Authenticated data (requires BUGCROWD_EMAIL, PASSWORD, TOTP_SECRET):
    - Full scope targets via /engagements/{handle}/target_groups.json
    - Hacktivity via /engagements/{handle}/hacktivity.json

The provider works in degraded mode without credentials — it returns
whatever it can scrape from public pages.
"""

import json
import re
import sys
from html import unescape as html_unescape
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import quote

from models import (
    AssetType, HacktivityEntry, Platform, ProgramPolicy, ProgramScope,
    ScopeAsset, Severity,
)
from providers.base import PlatformProvider

BASE_URL = "https://bugcrowd.com"
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL, "p1": Severity.CRITICAL,
    "high": Severity.HIGH, "p2": Severity.HIGH,
    "medium": Severity.MEDIUM, "p3": Severity.MEDIUM,
    "low": Severity.LOW, "p4": Severity.LOW,
    "informational": Severity.INFO, "p5": Severity.INFO,
}

TARGET_TYPE_MAP = {
    "website": AssetType.URL,
    "api": AssetType.URL,
    "url": AssetType.URL,
    "android": AssetType.MOBILE_APP,
    "ios": AssetType.MOBILE_APP,
    "hardware": AssetType.HARDWARE,
    "other": AssetType.OTHER,
}


def _deep_get(data, *keys):
    """Safely navigate nested dicts, returning None on miss."""
    for k in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(k)
    return data


def _html_to_text(html_str: str) -> str:
    """Convert HTML-escaped brief content to plain text."""
    text = html_str.replace("\\u003c", "<").replace("\\u003e", ">")
    text = text.replace("\\u0026", "&").replace("\\n", "\n")
    text = html_unescape(text)
    text = re.sub(r"<[^>]+>", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_urls(text: str) -> list[str]:
    """Pull URLs from text that look like scope targets."""
    urls = []
    for m in re.finditer(
        r"https?://[\w\-.*]+\.\w+(?:/[\w\-./]*)?", text,
    ):
        url = m.group(0).rstrip("/")
        if "bugcrowd" not in url and url not in urls:
            urls.append(url)
    return urls


class BugcrowdProvider(PlatformProvider):
    """Bugcrowd provider: public scraping + optional auth session.

    If credentials are provided (email/password/totp_secret), the
    provider logs in to BugCrowd and can fetch full scope targets
    and hacktivity. Without credentials it falls back to public
    HTML scraping (brief/policy only).
    """

    platform_name = "Bugcrowd"
    platform_id = "bugcrowd"

    def __init__(
        self,
        email: str = "",
        password: str = "",
        totp_secret: str = "",
    ):
        super().__init__()
        self._session = None
        if email and password and totp_secret:
            from providers.bugcrowd_auth import BugcrowdSession
            self._session = BugcrowdSession(email, password, totp_secret)

    @property
    def is_configured(self) -> bool:
        return True  # Public scraping always works

    @property
    def has_auth(self) -> bool:
        return self._session is not None

    # --- Public (unauthenticated) helpers ---

    def _get_html(self, url: str) -> str:
        """Fetch a public Bugcrowd page."""
        req = Request(url, headers={
            "User-Agent": _UA,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
        })
        try:
            with urlopen(req, timeout=30) as resp:
                return resp.read().decode()
        except HTTPError as e:
            if e.code == 404:
                return ""
            raise

    def _extract_brief_props(self, html: str) -> dict:
        """Extract data-props JSON from the engagement brief
        React component on the public page.
        """
        if not html:
            return {}

        class_marker = "ResearcherEngagementBrief"
        class_pos = html.find(class_marker)
        if class_pos < 0:
            return {}

        search_start = max(0, class_pos - 15000)
        chunk = html[search_start:class_pos]

        props_attr = "data-props='"
        pi = chunk.rfind(props_attr)
        if pi < 0:
            return {}

        abs_start = search_start + pi + len(props_attr)
        end_marker = f"' data-react-class='{class_marker}'"
        abs_end = html.find(end_marker, abs_start)
        if abs_end < 0:
            return {}

        raw = html[abs_start:abs_end]
        try:
            return json.loads(html_unescape(raw))
        except (json.JSONDecodeError, ValueError):
            return {}

    def _extract_api_endpoints(self, html: str) -> dict:
        """Extract data-api-endpoints JSON from the page."""
        m = re.search(r"data-api-endpoints='([^']+)'", html)
        if not m:
            return {}
        try:
            return json.loads(html_unescape(m.group(1)))
        except (json.JSONDecodeError, ValueError):
            return {}

    def _extract_brief_version_url(self, html: str) -> str:
        """Extract the scope/brief document URL from the page.

        The engagement page embeds API endpoints including
        getBriefVersionDocument which points to the version
        changelog. Appending ``.json`` returns structured scope
        data (targets, descriptions, inScope flags).
        """
        endpoints = self._extract_api_endpoints(html)
        path = _deep_get(
            endpoints,
            "engagementBriefApi",
            "getBriefVersionDocument",
        ) or ""
        if path:
            return path + ".json"
        return ""

    def _program_name_from_html(
        self, html: str, fallback: str,
    ) -> str:
        m = re.search(r"<title>([^<]+)</title>", html)
        if m:
            name = re.sub(
                r"\s*[-|\u2013]?\s*Bugcrowd.*$", "",
                m.group(1),
            ).strip()
            name = re.sub(r"^Bug Bounty:\s*", "", name).strip()
            return name or fallback
        return fallback

    def _engagement_url(self, handle: str) -> str:
        return f"{BASE_URL}/engagements/{quote(handle)}"

    # --- Authenticated helpers ---

    def _auth_get_json(self, url: str) -> dict:
        """Authenticated JSON GET via the session. Returns {} on
        failure or if no session is available. Errors are logged to
        stderr so silent auth regressions are diagnosable.
        """
        if not self._session:
            return {}
        try:
            return self._session.get_json(url)
        except Exception as e:
            print(
                f"[bugcrowd] auth GET {url} failed: "
                f"{type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return {}

    def _auth_get_html(self, url: str) -> str:
        """Authenticated HTML GET via the session. Errors logged to stderr."""
        if not self._session:
            return ""
        try:
            return self._session.get(url)
        except Exception as e:
            print(
                f"[bugcrowd] auth GET {url} failed: "
                f"{type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return ""

    # --- Provider interface ---

    async def get_scope(
        self, program_handle: str,
    ) -> Optional[ProgramScope]:
        url = self._engagement_url(program_handle)
        html = self._get_html(url)
        if not html:
            return None

        props = self._extract_brief_props(html)
        name = self._program_name_from_html(html, program_handle)

        in_scope: list[ScopeAsset] = []
        out_of_scope: list[ScopeAsset] = []

        # Strategy 1: authenticated scope via brief document API
        if self.has_auth:
            brief_url = self._extract_brief_version_url(html)
            if brief_url:
                doc = self._auth_get_json(
                    f"{BASE_URL}{brief_url}",
                )
                scope_items = _deep_get(doc, "data", "scope") or []
                for scope_group in scope_items:
                    if not isinstance(scope_group, dict):
                        continue
                    is_in = scope_group.get("inScope", True)
                    targets = scope_group.get("targets", [])
                    for t in targets:
                        if not isinstance(t, dict):
                            continue
                        asset_name = (
                            t.get("uri")
                            or t.get("name")
                            or t.get("target", "")
                        )
                        if not asset_name:
                            continue
                        cat = str(
                            t.get("category", "other"),
                        ).lower()
                        # Build notes from description + tags
                        notes_parts = []
                        desc = t.get("description") or ""
                        if desc:
                            notes_parts.append(desc)
                        tags = t.get("tags") or []
                        if tags:
                            tag_names = [
                                tg.get("name", "") for tg in tags
                                if isinstance(tg, dict) and tg.get("name")
                            ]
                            if tag_names:
                                notes_parts.append(
                                    f"tags: {', '.join(tag_names)}"
                                )

                        asset = ScopeAsset(
                            asset=asset_name,
                            asset_type=TARGET_TYPE_MAP.get(
                                cat, AssetType.OTHER,
                            ),
                            eligible=is_in,
                            notes="; ".join(notes_parts),
                        )
                        if is_in:
                            in_scope.append(asset)
                        else:
                            out_of_scope.append(asset)

        # Strategy 2: extract URLs from the public brief
        if not in_scope:
            desc = _deep_get(
                props, "earlyFetchProps", "description",
            )
            if desc:
                for target_url in _extract_urls(desc):
                    in_scope.append(ScopeAsset(
                        asset=target_url,
                        asset_type=AssetType.URL,
                        eligible=True,
                        notes="extracted from program brief",
                    ))

        return ProgramScope(
            platform=Platform.BUGCROWD,
            program_handle=program_handle,
            program_name=name,
            program_url=url,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )

    async def get_policy(
        self, program_handle: str,
    ) -> Optional[ProgramPolicy]:
        url = self._engagement_url(program_handle)
        html = self._get_html(url)
        if not html:
            return None

        props = self._extract_brief_props(html)
        efp = _deep_get(props, "earlyFetchProps") or {}

        desc_html = efp.get("description", "")
        policy_text = _html_to_text(desc_html) if desc_html else ""

        header = efp.get("headerProps", {})
        tagline = header.get("tagline", "")
        if tagline and policy_text:
            policy_text = f"{tagline}\n\n{policy_text}"

        safe_harbor = False
        restrictions: list[str] = []

        # Authenticated: pull full policy from brief document
        # which includes targetsOverview (rules, guidelines,
        # out-of-scope, safe harbor) and safeHarborStatus.
        if self.has_auth:
            brief_url = self._extract_brief_version_url(html)
            if brief_url:
                doc = self._auth_get_json(f"{BASE_URL}{brief_url}")
                brief = _deep_get(doc, "data", "brief") or {}

                overview = brief.get("targetsOverview", "")
                if overview:
                    overview_text = _html_to_text(overview)
                    policy_text += f"\n\n{overview_text}"

                sh = brief.get("safeHarborStatus", {})
                if isinstance(sh, dict):
                    safe_harbor = sh.get("status") in (
                        "full", "partial",
                    )

        return ProgramPolicy(
            platform=Platform.BUGCROWD,
            program_handle=program_handle,
            policy_text=(
                policy_text
                or f"See {url} for full program policy."
            ),
            safe_harbor=safe_harbor,
            testing_restrictions=restrictions,
        )

    async def search_hacktivity(
        self,
        program_handle: str,
        query: str = "",
        limit: int = 50,
    ) -> list[HacktivityEntry]:
        # Try authenticated hacktivity endpoint
        if self.has_auth:
            ha_url = (
                f"{BASE_URL}/engagements/"
                f"{quote(program_handle)}/hacktivity.json"
            )
            data = self._auth_get_json(ha_url)
            items = (
                data.get("hacktivity")
                or data.get("submissions")
                or data.get("data")
                or []
            )
            entries = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                title = item.get("title", "")
                if query and query.lower() not in title.lower():
                    continue
                entries.append(HacktivityEntry(
                    report_id=str(item.get("id", "")),
                    title=title,
                    severity=SEVERITY_MAP.get(
                        str(item.get("severity", "")).lower(),
                        Severity.NONE,
                    ),
                    state=item.get(
                        "state", item.get("status", ""),
                    ),
                    bounty_amount=(
                        item.get("amount_awarded")
                        or item.get("bounty")
                    ),
                    vulnerability_type=item.get(
                        "vrt_id",
                        item.get("vulnerability_type", ""),
                    ),
                    platform=Platform.BUGCROWD,
                ))
                if len(entries) >= limit:
                    break
            return entries

        # No auth — hacktivity not available from public HTML
        return []
