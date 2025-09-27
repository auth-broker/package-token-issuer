from abc import ABC, abstractmethod
from typing import Generator, Generic, TypeVar

from pydantic import BaseModel, Field

from ab_core.auth_client.oauth2.client import OAuth2Client
from ab_core.auth_client.oauth2.schema.authorize import OAuth2AuthorizeResponse
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.auth_flow.oauth2.flow import OAuth2Flow
from ab_core.auth_flow.oauth2.schema.auth_code_stage import AuthCodeStageInfo
from ab_core.cache.caches.base import CacheSession

T = TypeVar("T")


class TokenIssuerBase(BaseModel, Generic[T], ABC):
    @abstractmethod
    def authenticate(self, user_id: str) -> T: ...

    @abstractmethod
    def refresh(self, user_id: str) -> T: ...


class OAuth2TokenIssuerBase(TokenIssuerBase[OAuth2Token], ABC):
    oauth2_flow: OAuth2Flow
    oauth2_client: OAuth2Client

    identity_provider: str = "Google"
    response_type: str = "code"
    scope: str = "openid email profile"

    # Subclasses must accept the optional cache_session
    @abstractmethod
    def _build_authorize(
        self, *, cache_session: CacheSession | None = None
    ) -> OAuth2AuthorizeResponse: ...

    @abstractmethod
    def _exchange_code(
        self,
        code: str,
        authorize: OAuth2AuthorizeResponse,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token: ...

    def authenticate(
        self,
        *,
        cache_session: CacheSession | None = None,
    ) -> Generator[AuthCodeStageInfo | OAuth2Token, None, OAuth2Token]:
        # 1) Build the authorize request via the client
        authorize = self._build_authorize(cache_session=cache_session)

        # 2) Drive the login flow
        auth_code_stage = yield from self.oauth2_flow.get_code(authorize.url)
        code = auth_code_stage.auth_code

        # 3) Exchange for tokens
        tokens = self._exchange_code(code, authorize, cache_session=cache_session)

        # 4) Emit final token
        yield tokens
        return tokens
