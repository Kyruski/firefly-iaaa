from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidators
from firefly_iaaa.domain.entity.bearer_token import BearerToken


def test_get_original_scopes(validator: OauthlibRequestValidators, oauth_request_list: List[Request], bearer_tokens_list: List[BearerToken]):
    for i in range(6):
        bearer_token = bearer_tokens_list[i]['active']

        # Check the correct scopes are returned
        assert validator.get_original_scopes(bearer_token.refresh_token, oauth_request_list[i]) == bearer_token.scopes
        # Check wrong token returns None
        assert validator.get_original_scopes('bearer_token.refresh_token', oauth_request_list[i]) is None
