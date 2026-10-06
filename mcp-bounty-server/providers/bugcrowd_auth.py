"""BugCrowd session authentication via Okta OIDC flow.

Bugcrowd consolidated auth onto Okta: the GET against
``identity.bugcrowd.com/login`` 302-redirects straight to the Okta
authorize page (``login.hackers.bugcrowd.com/oauth2/default/v1/authorize``)
with the IDX ``stateToken`` already embedded in the page body. The
legacy POST username/password against identity.bugcrowd.com was retired
and now returns HTTP 405.

Login chain:
  1. GET  identity.bugcrowd.com/login → Okta IDX page (stateToken)
  2. POST login.hackers.bugcrowd.com/idp/idx/introspect
  3. POST .../idp/idx/identify          (email)
  4. POST .../idp/idx/challenge/answer  (password, if challenged)
  5. POST .../idp/idx/challenge/answer  (TOTP)
  6. GET  .../login/token/redirect      → session cookies

Environment variables:
    BUGCROWD_EMAIL       — BugCrowd account email
    BUGCROWD_PASSWORD    — BugCrowd account password
    BUGCROWD_TOTP_SECRET — Base32-encoded TOTP secret for 2FA
"""

import http.cookiejar
import json
import re
import subprocess
import time
from urllib.error import HTTPError
from urllib.request import (
    HTTPCookieProcessor, HTTPRedirectHandler,
    Request, build_opener,
)

IDENTITY_URL = "https://identity.bugcrowd.com"
OKTA_BASE = "https://login.hackers.bugcrowd.com"
BASE_URL = "https://bugcrowd.com"
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:82.0) "
    "Gecko/20100101 Firefox/82.0"
)

_SESSION_TTL = 20 * 60  # Re-auth 10 min before expiry


class _NoRedirect(HTTPRedirectHandler):
    """Capture redirects instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class BugcrowdSession:
    """Authenticated BugCrowd session via Okta OIDC + TOTP."""

    def __init__(self, email: str, password: str, totp_secret: str):
        self.email = email
        self.password = password
        self.totp_secret = totp_secret

        self._jar = http.cookiejar.CookieJar()
        self._opener = build_opener(HTTPCookieProcessor(self._jar))
        self._no_redir = build_opener(
            HTTPCookieProcessor(self._jar), _NoRedirect(),
        )
        self._authenticated = False
        self._auth_time: float = 0
        self._last_login_attempt: float = 0
        self._cookie_header: str = ""

    @property
    def is_valid(self) -> bool:
        if not self._authenticated:
            return False
        return (time.time() - self._auth_time) < _SESSION_TTL

    # --- Low-level helpers ---

    def _totp(self) -> str:
        proc = subprocess.run(
            ["oathtool", "--totp", "-b", self.totp_secret],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"oathtool failed: {proc.stderr}")
        return proc.stdout.strip()

    def _http(
        self, method: str, url: str,
        headers: dict = None, data=None,
        follow_redirects: bool = True,
    ) -> dict:
        """Make an HTTP request and return parsed result."""
        hdrs = {"User-Agent": _UA}
        if headers:
            hdrs.update(headers)

        req = Request(url, headers=hdrs, method=method)
        if data is not None:
            if isinstance(data, dict):
                req.data = json.dumps(data).encode()
            elif isinstance(data, str):
                req.data = data.encode()
            else:
                req.data = data

        opener = self._opener if follow_redirects else self._no_redir
        try:
            resp = opener.open(req, timeout=30)
            raw = resp.read().decode()
            return {
                "status": resp.status,
                "url": resp.url,
                "location": resp.headers.get("Location", ""),
                "body": raw,
                "json": _try_json(raw),
            }
        except HTTPError as e:
            raw = e.read().decode() if e.fp else ""
            return {
                "status": e.code,
                "url": url,
                "location": e.headers.get("Location", ""),
                "body": raw,
                "json": _try_json(raw),
            }

    def _build_cookie_header(self) -> str:
        """Build a Cookie header string for bugcrowd.com."""
        seen = set()
        parts = []
        for c in self._jar:
            if "bugcrowd.com" in c.domain and c.name not in seen:
                seen.add(c.name)
                parts.append(f"{c.name}={c.value}")
        return "; ".join(parts)

    # --- Login flow ---

    def login(self):
        """Full Okta OIDC login: identity → Okta IDX → session cookies."""

        # Step 1: GET identity login → 302 chain ends on Okta authorize
        # page; the response body is the IDX login form with stateToken
        # already embedded. If a persisted session validates us, the
        # chain instead ends back on bugcrowd.com.
        login_url = (
            f"{IDENTITY_URL}/login?user_hint=researcher"
            f"&returnTo=https%3A%2F%2Fbugcrowd.com%2Fdashboard"
        )
        r = self._http("GET", login_url)
        okta_html = r["body"]
        okta_url = r["url"]

        if (
            "bugcrowd.com" in okta_url
            and "identity.bugcrowd.com" not in okta_url
            and "login.hackers.bugcrowd.com" not in okta_url
        ):
            self._authenticated = True
            self._auth_time = time.time()
            self._cookie_header = self._build_cookie_header()
            return

        state_token = ""
        m = re.search(r'"stateToken"\s*:\s*"([^"]+)"', okta_html)
        if m:
            state_token = m.group(1).replace("\\x2D", "-")
        if not state_token:
            raise RuntimeError(
                f"No stateToken on Okta login page (url={okta_url[:120]!r})"
            )

        # Step 2: Okta IDX introspect
        r = self._http(
            "POST", f"{OKTA_BASE}/idp/idx/introspect",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": OKTA_BASE,
            },
            data={"stateToken": state_token},
        )
        idx = r["json"] or {}
        state_handle = idx.get("stateHandle", state_token)

        # Step 3: Identify (if remediation exists)
        remediations = _get_remediations(idx)
        if "identify" in remediations:
            r = self._http(
                "POST", f"{OKTA_BASE}/idp/idx/identify",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Requested-With": "XMLHttpRequest",
                },
                data={
                    "identifier": self.email,
                    "stateHandle": state_handle,
                    "stateToken": state_token,
                },
            )
            idx = r["json"] or {}
            state_handle = idx.get("stateHandle", state_handle)

        # Step 4: Password challenge (if needed)
        remediations = _get_remediations(idx)
        if "challenge-authenticator" in remediations:
            current = idx.get("currentAuthenticator", {})
            auth_type = (
                current.get("value", {})
                .get("type", "")
            )
            if auth_type == "password":
                r = self._http(
                    "POST",
                    f"{OKTA_BASE}/idp/idx/challenge/answer",
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "X-Requested-With": "XMLHttpRequest",
                    },
                    data={
                        "credentials": {"passcode": self.password},
                        "stateHandle": state_handle,
                        "stateToken": state_token,
                    },
                )
                idx = r["json"] or {}
                state_handle = idx.get("stateHandle", state_handle)

        # Step 5: TOTP challenge
        code = self._totp()
        r = self._http(
            "POST", f"{OKTA_BASE}/idp/idx/challenge/answer",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
            },
            data={
                "credentials": {"passcode": code},
                "stateHandle": state_handle,
                "stateToken": state_token,
            },
        )
        idx = r["json"] or {}

        if idx.get("errorSummary"):
            raise RuntimeError(
                f"Okta TOTP failed: {idx['errorSummary']}"
            )

        # Step 6: Token redirect → session cookies
        r = self._http(
            "GET",
            f"{OKTA_BASE}/login/token/redirect"
            f"?stateToken={state_handle}",
            headers={"Referer": okta_url},
        )

        self._cookie_header = self._build_cookie_header()
        if not self._cookie_header:
            raise RuntimeError(
                "Login completed but no session cookies received"
            )

        self._authenticated = True
        self._auth_time = time.time()

    # --- Public API ---

    def ensure_session(self):
        if not self.is_valid:
            # Prevent rapid re-login attempts that trigger lockouts.
            # Wait at least 35s between logins (TOTP window = 30s).
            elapsed = time.time() - self._last_login_attempt
            if self._last_login_attempt and elapsed < 35:
                wait = 35 - elapsed
                time.sleep(wait)
            self._last_login_attempt = time.time()
            self.login()

    def get(self, url: str) -> str:
        """Authenticated GET, returns response body."""
        self.ensure_session()
        req = Request(url, headers={
            "User-Agent": _UA,
            "Accept": "text/html, application/json, */*",
            "Cookie": self._cookie_header,
        })
        with self._opener.open(req, timeout=30) as resp:
            return resp.read().decode()

    def get_json(self, url: str) -> dict:
        """Authenticated GET, returns parsed JSON."""
        self.ensure_session()
        req = Request(url, headers={
            "User-Agent": _UA,
            "Accept": "application/json",
            "Cookie": self._cookie_header,
        })
        try:
            with self._opener.open(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            if e.code == 401:
                self._authenticated = False
                self.login()
                req2 = Request(url, headers={
                    "User-Agent": _UA,
                    "Accept": "application/json",
                    "Cookie": self._cookie_header,
                })
                with self._opener.open(req2, timeout=30) as resp:
                    return json.loads(resp.read().decode())
            raise


def _try_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _get_remediations(idx: dict) -> set:
    """Extract remediation type names from Okta IDX response."""
    names = set()
    for rem in idx.get("remediation", {}).get("value", []):
        name = rem.get("name", "")
        if name:
            names.add(name)
    return names
