"""Abstract base class for bug bounty platform providers."""

from abc import ABC, abstractmethod
from typing import Optional
from models import ProgramScope, ProgramPolicy, HacktivityEntry


class PlatformProvider(ABC):
    """Base class for all bug bounty platform API providers."""

    def __init__(self, api_key: Optional[str] = None, api_secret: Optional[str] = None):
        self.api_key = api_key
        self.api_secret = api_secret

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Human-readable platform name."""

    @property
    @abstractmethod
    def platform_id(self) -> str:
        """Machine identifier matching Platform enum value."""

    @property
    def is_configured(self) -> bool:
        """Whether this provider has valid credentials."""
        return self.api_key is not None

    @abstractmethod
    async def get_scope(self, program_handle: str) -> Optional[ProgramScope]:
        """Fetch program scope (in-scope and out-of-scope assets)."""

    @abstractmethod
    async def get_policy(self, program_handle: str) -> Optional[ProgramPolicy]:
        """Fetch program policy and testing guidelines."""

    @abstractmethod
    async def search_hacktivity(
        self, program_handle: str, query: str = "", limit: int = 50
    ) -> list[HacktivityEntry]:
        """Search disclosed reports / hacktivity for duplicate checking."""

    async def get_all(self, program_handle: str) -> dict:
        """Fetch scope, policy, and hacktivity in one call."""
        scope = await self.get_scope(program_handle)
        policy = await self.get_policy(program_handle)
        hacktivity = await self.search_hacktivity(program_handle)
        return {"scope": scope, "policy": policy, "hacktivity": hacktivity}
