from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator, Generator
from typing import Generic, TypeVar, override

from pydantic import BaseModel

from ab_core.auth_client.oauth2.client import OAuth2Client
from ab_core.auth_client.oauth2.schema.authorize import OAuth2AuthorizeResponse
from ab_core.auth_client.oauth2.schema.refresh import RefreshTokenRequest
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.auth_flow.oauth2.flow import OAuth2Flow
from ab_core.auth_flow.oauth2.schema.auth_code_stage import AuthCodeStageInfo
from ab_core.cache.caches.base import CacheAsyncSession, CacheSession

T = TypeVar("T")


class TokenIssuerBase(BaseModel, Generic[T], ABC):
    @abstractmethod
    def authenticate(
        self,
        *,
        cache_session: CacheSession | None = None,
    ) -> Generator[AuthCodeStageInfo | T, None, None]: ...

    # NEW: async authenticate
    @abstractmethod
    async def authenticate_async(
        self,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> AsyncGenerator[AuthCodeStageInfo | T, None]: ...

    @abstractmethod
    def refresh(
        self,
        request: RefreshTokenRequest,
        *,
        cache_session: CacheSession | None = None,
    ) -> Generator[T, None, None]: ...

    # NEW: async refresh
    @abstractmethod
    async def refresh_async(
        self,
        request: RefreshTokenRequest,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> AsyncGenerator[T, None]: ...


class OAuth2TokenIssuerBase(TokenIssuerBase[OAuth2Token], ABC):
    oauth2_flow: OAuth2Flow
    oauth2_client: OAuth2Client

    identity_provider: str = "Google"
    response_type: str = "code"
    scope: str = "openid email profile"

    # Subclasses must accept the optional cache_session
    @abstractmethod
    def _build_authorize(
        self,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2AuthorizeResponse: ...

    # NEW: async helper to build authorize
    @abstractmethod
    async def _build_authorize_async(
        self,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> OAuth2AuthorizeResponse: ...

    @abstractmethod
    def _exchange_code(
        self,
        code: str,
        authorize: OAuth2AuthorizeResponse,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token: ...

    # NEW: async helper to exchange code
    @abstractmethod
    async def _exchange_code_async(
        self,
        code: str,
        authorize: OAuth2AuthorizeResponse,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> OAuth2Token: ...

    @override
    def authenticate(
        self,
        *,
        cache_session: CacheSession | None = None,
    ) -> Generator[AuthCodeStageInfo | OAuth2Token, None, None]:
        # 1) Build the authorize request via the client
        authorize = self._build_authorize(
            cache_session=cache_session,
        )

        # 2) Drive the login flow
        for stage in self.oauth2_flow.get_code(str(authorize.url)):
            yield stage
        code = stage.auth_code  # last stage is DONE

        # 3) Exchange for tokens
        tokens = self._exchange_code(
            code,
            authorize,
            cache_session=cache_session,
        )

        # 4) Emit final token
        yield tokens
        # @breaking:    >=0.2.0 no longer includes the return type from the generator.
        #               this is due to wanting more consistency with the async protocol
        return None

    # NEW: async authenticate flow
    @override
    async def authenticate_async(
        self,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> AsyncGenerator[AuthCodeStageInfo | OAuth2Token, None]:
        # 1) Build the authorize request (async)
        authorize = await self._build_authorize_async(cache_session=cache_session)

        # 2) Drive the login flow (async)
        last_stage: AuthCodeStageInfo | None = None
        async for stage in self.oauth2_flow.get_code_async(str(authorize.url)):
            last_stage = stage
            yield stage

        if last_stage is None or not hasattr(last_stage, "auth_code"):
            raise RuntimeError("OAuth2 flow did not yield an auth code stage")

        code = last_stage.auth_code  # type: ignore[attr-defined]

        # 3) Exchange for tokens (async)
        tokens = await self._exchange_code_async(
            code,
            authorize,
            cache_session=cache_session,
        )

        # 4) Emit final token
        yield tokens
        return

    @override
    def refresh(
        self,
        request: RefreshTokenRequest,
        *,
        cache_session: CacheSession | None = None,
    ) -> Generator[AuthCodeStageInfo | OAuth2Token, None, None]:
        # for now we just call the refresh token url directly, without channeling it through the auth flow.
        # this should be sufficient, but I'm thinking if they have SSL pinning or any CORS, it might be ncessary
        # to run this request through the auth flow. Then, the impersonation would enable refreshing a token within
        # a browser context.
        tokens = self.oauth2_client.refresh(
            request,
            cache_session=cache_session,
        )
        yield tokens
        # @breaking:    >=0.2.0 no longer includes the return type from the generator.
        #               this is due to wanting more consistency with the async protocol
        return None

    # NEW: async refresh passthrough
    @override
    async def refresh_async(
        self,
        request: RefreshTokenRequest,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> AsyncGenerator[OAuth2Token, None]:
        tokens = await self.oauth2_client.refresh_async(
            request,
            cache_session=cache_session,
        )
        yield tokens
        return
