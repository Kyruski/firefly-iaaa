from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User
from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator


def test_validate_bearer_token(validator: OauthlibRequestValidator, oauth_request_list: List[Request], bearer_tokens_list: List[BearerToken], user_list: List[User], client_list: List[Client]):

    #Test 3 the active, expired, and invalid tokens
    for x in range(3):
        #Test 2 token types
        for t in range(2):
            bearer_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
            bearer_token = bearer_tokens_list[-1][bearer_selector]
            assert_request_empty(oauth_request_list[-1])
            token = bearer_token.refresh_token if t == 0 else bearer_token.access_token
            assert validator.validate_bearer_token(token, bearer_token.scopes, oauth_request_list[-1]) == (x == 0)
            assert (oauth_request_list[-1].user == user_list[6]) == (x == 0)
            assert (oauth_request_list[-1].client == client_list[-1]) == (x == 0)
            assert (oauth_request_list[-1].scopes == bearer_token.scopes) == (x == 0)

            reset_request(oauth_request_list[-1])
            assert validator.validate_bearer_token('token', bearer_token.scopes, oauth_request_list[-1]) == False
            assert_request_empty(oauth_request_list[-1])

            assert validator.validate_bearer_token(token, [*bearer_token.scopes, 'abc'], oauth_request_list[-1]) == False
            assert_request_empty(oauth_request_list[-1])
            assert validator.validate_bearer_token(token, 'aaaaaa', oauth_request_list[-1]) == False
            assert_request_empty(oauth_request_list[-1])

def assert_request_empty(request):
    assert request.client is None
    assert request.user is None
    assert request.scopes is None

def reset_request(request):
    request.client = None
    request.user = None
    request.scopes = None