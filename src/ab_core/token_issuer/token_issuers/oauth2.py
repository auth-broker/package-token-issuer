from typing import Literal, override

from ab_core.auth_client.oauth2.schema.authorize import (
    OAuth2AuthorizeResponse,
    OAuth2BuildAuthorizeRequest,
)
from ab_core.auth_client.oauth2.schema.exchange import OAuth2ExchangeCodeRequest
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.cache.caches.base import CacheSession
from ab_core.token_issuer.schema.token_issuer_type import TokenIssuerType

from .base import OAuth2TokenIssuerBase


class OAuth2TokenIssuer(OAuth2TokenIssuerBase):
    type: Literal[TokenIssuerType.OAUTH2] = TokenIssuerType.OAUTH2

    @override
    def _build_authorize(
        self, *, cache_session: CacheSession | None = None
    ) -> OAuth2AuthorizeResponse:
        req = OAuth2BuildAuthorizeRequest(
            scope=self.scope,
            response_type=self.response_type,
            extra_params={"identity_provider": self.identity_provider},
        )
        return self.oauth2_client.build_authorize_request(req, cache_session=cache_session)

    @override
    def _exchange_code(
        self,
        code: str,
        authorize: OAuth2AuthorizeResponse,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token:
        return self.oauth2_client.exchange_code(
            OAuth2ExchangeCodeRequest(code=code),
            cache_session=cache_session,
        )
