from abc import ABC, abstractmethod
from typing import Generator, Generic, TypeVar

from pydantic import BaseModel, Field

from obo_core.auth_client.oauth2.client import OAuth2Client
from obo_core.auth_client.oauth2.schema.authorize import OAuth2AuthorizeResponse
from obo_core.auth_client.oauth2.schema.token import OAuth2Token
from obo_core.auth_flow.oauth2.flow import OAuth2Flow
from obo_core.auth_flow.oauth2.schema.auth_code_stage import AuthCodeStageInfo
from obo_core.cache.caches.base import CacheSession
from obo_core.token_store.oauth2.store import OAuth2TokenStore

T = TypeVar("T")


class TokenIssuerBase(BaseModel, Generic[T], ABC):
    @abstractmethod
    def authenticate(self, user_id: str) -> T: ...

    @abstractmethod
    def refresh(self, user_id: str) -> T: ...


class OAuth2TokenIssuerBase(TokenIssuerBase[OAuth2Token], ABC):
    oauth2_flow: OAuth2Flow
    oauth2_client: OAuth2Client
    token_store: OAuth2TokenStore | None = Field(
        default=None,
    )

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
        user_id: str,
        connection_id: str,
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
        if self.token_store is not None:
            self.token_store.save(user_id, connection_id, tokens)

        # 4) Emit final token
        yield tokens
        return tokens

    def refresh(
        self, user_id: str, connection_id: str
    ) -> Generator[AuthCodeStageInfo | OAuth2Token, None, OAuth2Token]:
        stored = self.token_store.load(user_id, connection_id)
        if not stored or not stored.refresh_token:
            tokens = yield from self.authenticate(user_id, connection_id)
            return tokens

        try:
            tokens = self.oauth2_client.refresh_token(stored.refresh_token)
            self.token_store.save(user_id, connection_id, tokens)
            yield tokens
            return tokens
        except Exception:
            self.token_store.clear(user_id, connection_id)
            tokens = yield from self.authenticate(user_id, connection_id)
            return tokens
