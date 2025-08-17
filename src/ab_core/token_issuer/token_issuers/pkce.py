from typing import Literal, override

from ab_core.auth_client.oauth2.client.pkce import PKCEOAuth2Client
from ab_core.auth_client.oauth2.schema.authorize import (
    PKCEAuthorizeResponse,
    PKCEBuildAuthorizeRequest,
)
from ab_core.auth_client.oauth2.schema.exchange import PKCEExchangeCodeRequest
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.cache.caches.base import CacheSession
from ab_core.token_issuer.schema.token_issuer_type import TokenIssuerType

from .base import OAuth2TokenIssuerBase


class PKCEOAuth2TokenIssuer(OAuth2TokenIssuerBase):
    type: Literal[TokenIssuerType.PKCE] = TokenIssuerType.PKCE

    oauth2_client: PKCEOAuth2Client

    @override
    def _build_authorize(
        self, *, cache_session: CacheSession | None = None
    ) -> PKCEAuthorizeResponse:
        req = PKCEBuildAuthorizeRequest(
            scope=self.scope,
            response_type=self.response_type,
            extra_params={"identity_provider": self.identity_provider},
        )
        return self.oauth2_client.build_authorize_request(req, cache_session=cache_session)

    @override
    def _exchange_code(
        self,
        code: str,
        authorize: PKCEAuthorizeResponse,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token:
        # Prefer state-based lookup; include verifier as fallback
        req = PKCEExchangeCodeRequest(
            code=code,
            state=authorize.state,
        )
        return self.oauth2_client.exchange_code(req, cache_session=cache_session)
