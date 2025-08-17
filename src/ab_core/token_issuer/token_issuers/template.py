from typing import Literal, override

from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.token_issuer.schema.token_issuer_type import (
    TokenIssuerType,
)

from .base import OAuth2TokenIssuerBase


class TemplateTokenIssuer(OAuth2TokenIssuerBase):
    type: Literal[TokenIssuerType.TEMPLATE] = TokenIssuerType.TEMPLATE

    @override
    def authenticate(self, user_id: str, connection_id: str) -> OAuth2Token:
        raise NotImplementedError()

    @override
    def refresh(self, user_id: str, connection_id: str) -> OAuth2Token:
        raise NotImplementedError()
