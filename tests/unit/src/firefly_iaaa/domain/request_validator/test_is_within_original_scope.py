from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.bearer_token import BearerToken

from firefly_iaaa.infrastructure.service.request_validator import OauthRequestValidators


def test_is_within_original_scope(validator: OauthRequestValidators, oauth_request_list: List[Request], bearer_tokens_list: List[dict]):

    for i in range(6):
        bearer_token = bearer_tokens_list[i]['active']

        # Check valid with correct scopes
        assert validator.is_within_original_scope(['fake-scopes', f'faker-scope{i}'], bearer_token.refresh_token, oauth_request_list[i]) == True
        
        # Check invalid with wrong/invalid token
        assert validator.is_within_original_scope(['fake-scopes', f'faker-scope{i}'], 'bearer_token.refresh_token', oauth_request_list[i]) == False

        # Check valid with incorrect scopes
        assert validator.is_within_original_scope(['fake-scopes', f'faker-scope{i + 1}'], bearer_token.refresh_token, oauth_request_list[i]) == False
        assert validator.is_within_original_scope(['fake-scopes', f'faker-scope{i}', 'abc'], bearer_token.refresh_token, oauth_request_list[i]) == False
        assert validator.is_within_original_scope(['abc'], bearer_token.refresh_token, oauth_request_list[i]) == False
