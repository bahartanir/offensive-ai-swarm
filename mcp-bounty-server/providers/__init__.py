"""Platform provider registry with lazy imports (O8)."""

import os
import importlib
from pathlib import Path

_PROVIDERS_DIR = Path(__file__).parent


def _try_import(module_name: str):
    """Import a provider module if it exists."""
    module_path = _PROVIDERS_DIR / f"{module_name}.py"
    if module_path.exists():
        return importlib.import_module(f"providers.{module_name}")
    return None


class _StubProvider:
    """Unconfigured provider placeholder."""
    def __init__(self, name, pid, env_hint=""):
        self.platform_name = name
        self.platform_id = pid
        self.is_configured = False

    async def get_scope(self, handle):
        return None
    async def get_policy(self, handle):
        return None
    async def search_hacktivity(self, handle, query="", limit=50):
        return []


def build_registry() -> dict:
    """Build provider registry. Only imports configured providers."""
    registry = {}

    # HackerOne
    if os.environ.get("HACKERONE_USERNAME") and os.environ.get("HACKERONE_TOKEN"):
        mod = _try_import("hackerone")
        if mod:
            registry["hackerone"] = mod.HackerOneProvider(
                api_username=os.environ["HACKERONE_USERNAME"],
                api_token=os.environ["HACKERONE_TOKEN"],
            )
        else:
            registry["hackerone"] = _StubProvider("HackerOne", "hackerone")
    else:
        registry["hackerone"] = _StubProvider("HackerOne", "hackerone")

    # Bugcrowd (public scraping + optional login with credentials)
    mod = _try_import("bugcrowd")
    if mod:
        registry["bugcrowd"] = mod.BugcrowdProvider(
            email=os.environ.get("BUGCROWD_EMAIL", ""),
            password=os.environ.get("BUGCROWD_PASSWORD", ""),
            totp_secret=os.environ.get("BUGCROWD_TOTP_SECRET", ""),
        )
    else:
        registry["bugcrowd"] = _StubProvider("Bugcrowd", "bugcrowd")

    # Immunefi (public API, always available if module exists)
    mod = _try_import("immunefi")
    if mod:
        registry["immunefi"] = mod.ImmunefiProvider()
    else:
        # Immunefi is in extra.py
        mod = _try_import("extra")
        if mod and hasattr(mod, "ImmunefiProvider"):
            registry["immunefi"] = mod.ImmunefiProvider()
        else:
            p = _StubProvider("Immunefi", "immunefi")
            p.is_configured = True  # Public API
            registry["immunefi"] = p

    # Intigriti and YesWeHack both live in providers/extra.py.
    # Intigriti API requires a bearer token; YesWeHack public programs are
    # reachable without one (token only needed for submission / private progs).
    extra_mod = _try_import("extra")

    if extra_mod and os.environ.get("INTIGRITI_TOKEN"):
        # INTIGRITI_SPA_COOKIE is optional. When set, the provider also uses
        # the SPA-private API to enrich scope/policy with program-specific
        # in-scope intro, out-of-scope rules, severity guidance, FAQ, and the
        # structured bounty table — none of which the read-only researcher
        # API exposes. Cookie auth lasts ~2 weeks before the user must
        # refresh it from devtools.
        registry["intigriti"] = extra_mod.IntigritiProvider(
            api_key=os.environ["INTIGRITI_TOKEN"],
            spa_cookie=os.environ.get("INTIGRITI_SPA_COOKIE") or None,
        )
    else:
        registry["intigriti"] = _StubProvider("Intigriti", "intigriti")

    if extra_mod:
        registry["yeswehack"] = extra_mod.YesWeHackProvider(
            api_key=os.environ.get("YESWEHACK_TOKEN") or None,
        )
    else:
        registry["yeswehack"] = _StubProvider("YesWeHack", "yeswehack")

    # Stub-only platforms
    for name, pid in [("Bugbase", "bugbase"), ("BugRap", "bugrap"), ("Cantina", "cantina"),
                       ("Code4rena", "code4rena"), ("Compass Security", "compass"),
                       ("GObugfree", "gobugfree"), ("HackenProof", "hackenproof"),
                       ("IssueHunt", "issuehunt"), ("PatchDay", "patchday"),
                       ("Remedy", "remedy"), ("Standoff365", "standoff365")]:
        registry[pid] = _StubProvider(name, pid)

    return registry


def get_provider(registry: dict, platform_id: str):
    return registry.get(platform_id)


def list_platforms(registry: dict) -> list[dict]:
    return [
        {
            "platform": p.platform_id,
            "name": p.platform_name,
            "configured": getattr(p, "is_configured", False),
            "type": "stub" if isinstance(p, _StubProvider) else "api",
        }
        for p in registry.values()
    ]
