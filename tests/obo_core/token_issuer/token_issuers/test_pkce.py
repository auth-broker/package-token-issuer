from uuid_extensions import uuid7

from obo_core.auth_client.oauth2.client.pkce import (
    PKCEOAuth2Client,
)
from obo_core.auth_client.oauth2.schema.oidc import OIDCConfig
from obo_core.auth_flow.oauth2.flow.playwright import (
    PlaywrightOAuth2Flow,
)
from obo_core.token_issuer.token_issuers.pkce import (
    PKCEOAuth2TokenIssuer,
)


def test_wemoney_authenticate():
    user_id, connection_id = uuid7(), uuid7()
    wemoney_config = OIDCConfig(
        client_id="247ffs2l6um22baifm5o7nhkgh",
        redirect_uri="https://app.wemoney.com.au/oauth_redirect",
        authorize_url="https://wemoney.auth.ap-southeast-2.amazoncognito.com/oauth2/authorize",
        token_url="https://wemoney.auth.ap-southeast-2.amazoncognito.com/oauth2/token",
    )

    issuer = PKCEOAuth2TokenIssuer(
        oauth2_client=PKCEOAuth2Client(
            config=wemoney_config,
        ),
        oauth2_flow=PlaywrightOAuth2Flow(
            idp_prefix="https://wemoney.auth.ap-southeast-2.amazoncognito.com/oauth2/idpresponse",
        ),
    )

    # 1. test getting the token
    token = issuer.authenticate(user_id, connection_id)

    # 2. test refreshing the token
    refreshed_token = issuer.refresh(user_id, connection_id)

    assert refreshed_token.refresh_token == token.refresh_token
