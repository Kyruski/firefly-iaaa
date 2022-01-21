from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.service.request_validator import OauthRequestValidators


def test_validate_grant_type(validator: OauthRequestValidators, oauth_request_list: List[Request]):
    grant_types = ['authorization_code', 'refresh_token', 'password', 'client_credentials']
    for i in range(6):
        for x in range(4):
            # Should be true/validated if i%4 == x, aka if the grant type in request is the grant type provided
            # OR if the provided grant type is refresh token and the grant type for the client is refresh, password, or client credentials (all grant types that can have a refresh grant)
            assert validator.validate_grant_type('', grant_types[x], oauth_request_list[i].client, oauth_request_list[i]) == (((i % 4) == x) or ((i in (2, 3, 4)) and (x == 1)))

            # Same as above, but with (x + 1) instead of (x) to check incorrect types (probably not needed)
            assert validator.validate_grant_type('', grant_types[(x + 1) % 4], oauth_request_list[i].client, oauth_request_list[i]) == (((i % 4) == ((x + 1) % 4)) or ((i in (2, 3, 4)) and (x + 1 == 1)))
