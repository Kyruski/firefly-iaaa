from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator
from firefly_iaaa.domain.entity.bearer_token import BearerToken


def test_get_original_scopes(validator: OauthlibRequestValidator, oauth_request_list: List[Request], bearer_tokens_list: List[BearerToken]):
    for i in range(6):
        for x in range(3):
            bearer_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
            bearer_token = bearer_tokens_list[i][bearer_selector]
            assert validator.get_original_scopes(bearer_token.refresh_token, oauth_request_list[i]) == bearer_token.scopes
            assert validator.get_original_scopes('bearer_token.refresh_token', oauth_request_list[i]) is None
