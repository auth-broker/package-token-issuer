from enum import StrEnum


class TokenIssuerType(StrEnum):
    OAUTH2 = "OAUTH2"
    PKCE = "PKCE"
    TEMPLATE = "TEMPLATE"
