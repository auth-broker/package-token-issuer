from typing import Annotated, Union

from pydantic import Discriminator

from .oauth2 import OAuth2TokenIssuer
from .pkce import PKCEOAuth2TokenIssuer
from .template import TemplateTokenIssuer

TokenIssuer = Annotated[
    PKCEOAuth2TokenIssuer | OAuth2TokenIssuer | TemplateTokenIssuer,
    Discriminator("type"),
]
