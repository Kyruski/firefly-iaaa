from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator


def test_validate_refresh_token(validator: OauthlibRequestValidator, oauth_request_list: List[Request], bearer_tokens_list: List[BearerToken]):
    for i in range(6):
        for x in range(3):
            bearer_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
            bearer_token = bearer_tokens_list[i][bearer_selector]
            assert oauth_request_list[i].user is None
            assert validator.validate_refresh_token(bearer_token.refresh_token, oauth_request_list[i].client, oauth_request_list[i]) == (x == 0)
            assert (oauth_request_list[i].user == bearer_token.user) == (x == 0)
            oauth_request_list[i].user = None
            assert oauth_request_list[i].user is None
            assert validator.validate_refresh_token(bearer_token.refresh_token, oauth_request_list[(i + 1) % 6].client, oauth_request_list[i]) == False #Check for wrong client
            assert oauth_request_list[i].user is None
            assert validator.validate_refresh_token('bearer_token.refresh_token', oauth_request_list[i].client, oauth_request_list[i]) == False
