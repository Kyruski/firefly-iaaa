from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User
from firefly_iaaa.domain.service.request_validator import OauthRequestValidators


def test_validate_bearer_token(validator: OauthRequestValidators, oauth_request_list: List[Request], bearer_tokens_list: List[dict], user_list: List[User], client_list: List[Client]):

    #Test the active, expired, and invalid tokens
    for x in range(3):
        #Test 2 token types (refresh and access)
        token_status = ['active', 'expired', 'invalid']
        for t in range(2):
            bearer_token = bearer_tokens_list[-1][token_status[x]]
            assert_request_empty(oauth_request_list[-1])
            token = bearer_token.refresh_token if t == 0 else bearer_token.access_token

            # Check if a bearer token is valid only if it's an 'active' token, and not 'expired' or 'invalid'
            assert validator.validate_bearer_token(token, bearer_token.scopes, oauth_request_list[-1]) == (x == 0 and t == 1)
            assert (oauth_request_list[-1].user == user_list[-2]) == (x == 0 and t == 1)
            assert (oauth_request_list[-1].client == client_list[-1]) == (x == 0 and t == 1)
            assert (oauth_request_list[-1].scopes == bearer_token.scopes) == (x == 0 and t == 1)
            reset_and_assert_empty(oauth_request_list[-1])

            # Check if a non-existent token fails
            assert validator.validate_bearer_token('token', bearer_token.scopes, oauth_request_list[-1]) == False
            assert_request_empty(oauth_request_list[-1])

            # Check if extra scopes fails
            assert validator.validate_bearer_token(token, [*bearer_token.scopes, 'abc'], oauth_request_list[-1]) == False
            assert_request_empty(oauth_request_list[-1])

            # Check if wrong scopes fails
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

def reset_and_assert_empty(request):
    reset_request(request)
    assert_request_empty(request)