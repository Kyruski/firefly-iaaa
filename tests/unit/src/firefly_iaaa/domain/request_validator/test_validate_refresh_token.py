from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.service.request_validator import OauthRequestValidators


def test_validate_refresh_token(validator: OauthRequestValidators, oauth_request_list: List[Request], bearer_tokens_list: List[dict]):
    token_status = ['active', 'expired', 'invalid']
    for i in range(6):
        for x in range(3):
            bearer_token = bearer_tokens_list[i][token_status[x]]
            assert oauth_request_list[i].user is None

            # Checking if refresh token is valid (only x == 0 is valid)
            assert validator.validate_refresh_token(bearer_token.refresh_token, oauth_request_list[i].client, oauth_request_list[i]) == (x == 0)
            assert (oauth_request_list[i].user == bearer_token.user) == (x == 0)

            # Resetting user on Request
            oauth_request_list[i].user = None
            assert oauth_request_list[i].user is None

            # Should not validate with mismatching token/client combo
            assert validator.validate_refresh_token(bearer_token.refresh_token, oauth_request_list[(i + 1) % 6].client, oauth_request_list[i]) == False #Check for wrong client
            assert oauth_request_list[i].user is None
            assert validator.validate_refresh_token('bearer_token.refresh_token', oauth_request_list[i].client, oauth_request_list[i]) == False
