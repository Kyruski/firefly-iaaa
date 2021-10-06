from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.bearer_token import BearerToken

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator


def test_is_within_original_scope(validator: OauthlibRequestValidator, oauth_request_list: List[Request], bearer_tokens_list: List[BearerToken]):

    for i in range(6):
        bearer_token = bearer_tokens_list[i]['active']

        assert validator.is_within_original_scope(['fake-scopes', f'faker-scope{i}'], bearer_token.refresh_token, oauth_request_list[i]) == True
        assert validator.is_within_original_scope(['fake-scopes', f'faker-scope{i}'], 'bearer_token.refresh_token', oauth_request_list[i]) == False
        assert validator.is_within_original_scope(['fake-scopes', f'faker-scope{i + 1}'], bearer_token.refresh_token, oauth_request_list[i]) == False
        assert validator.is_within_original_scope(['fake-scopes', f'faker-scope{i}', 'abc'], bearer_token.refresh_token, oauth_request_list[i]) == False
        assert validator.is_within_original_scope(['abc'], bearer_token.refresh_token, oauth_request_list[i]) == False
