import pytest

from ab_core.auth_client.oauth2.client.pkce import (
    PKCEOAuth2Client,
)
from ab_core.auth_client.oauth2.schema.oidc import OIDCConfig
from ab_core.auth_client.oauth2.schema.refresh import RefreshTokenRequest
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.auth_flow.oauth2.flow.impersonation import (
    ImpersonationOAuth2Flow,
)
from ab_core.impersonation.impersonator.playwright.browserless import (
    BrowserlessService,
    PlaywrightCDPBrowserlessImpersonator,
)
from ab_core.impersonation.impersonator.playwright.cdp import CDPGUIService
from ab_core.token_issuer.token_issuers.pkce import (
    PKCEOAuth2TokenIssuer,
)


@pytest.mark.asyncio
async def test_wemoney_authenticate(tmp_cache_async_session):
    issuer = PKCEOAuth2TokenIssuer(
        identity_provider="Google",
        response_type="code",
        scope="openid email profile",
        oauth2_client=PKCEOAuth2Client(
            config=OIDCConfig(
                client_id="247ffs2l6um22baifm5o7nhkgh",
                redirect_uri="https://app.wemoney.com.au/oauth_redirect",
                authorize_url="https://wemoney.auth.ap-southeast-2.amazoncognito.com/oauth2/authorize",
                token_url="https://wemoney.auth.ap-southeast-2.amazoncognito.com/oauth2/token",
            ),
        ),
        oauth2_flow=ImpersonationOAuth2Flow(
            idp_prefix="https://wemoney.auth.ap-southeast-2.amazoncognito.com/oauth2/idpresponse",
            timeout=600 * 1000,  # 600 seconds
            impersonator=PlaywrightCDPBrowserlessImpersonator(
                cdp_endpoint="wss://browserless.matthewcoulter.dev/?stealth=true&blockAds=true&ignoreHTTPSErrors=true&timezoneId=Australia/Sydney",
                cdp_gui_service=CDPGUIService(
                    base_url="https://browserless-gui.matthewcoulter.dev",
                ),
                cdp_headers=None,
                browserless_service=BrowserlessService(base_url="https://browserless.matthewcoulter.dev"),
            ),
        ),
    )

    # 1) test getting the token
    token: OAuth2Token | None = None
    async for item in issuer.authenticate_async(cache_session=tmp_cache_async_session):
        if isinstance(item, OAuth2Token):
            token = item
    assert token is not None

    # 2) refresh the token
    refreshed_token: OAuth2Token | None = None
    async for t in issuer.refresh_async(
        RefreshTokenRequest(refresh_token=token.refresh_token),
        cache_session=tmp_cache_async_session,
    ):
        refreshed_token = t
        break
    assert refreshed_token is not None

    # 3) Ensure the refresh token persists
    assert refreshed_token.refresh_token == token.refresh_token
