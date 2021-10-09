from __future__ import annotations
import os
from typing import List

from oauthlib.common import Request

from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidators


def test_validate_code(validator: OauthlibRequestValidators, oauth_request_list: List[Request], auth_codes_list: List[AuthorizationCode], registry):
    token_status = ['active', 'expired', 'invalid']
    for i in range(6):
        for x in range(3):
            auth_code = auth_codes_list[i][token_status[x]]
            assert_request_empty(oauth_request_list[i])

            #Should be valid if x is 0 (using valid code)
            assert validator.validate_code('', auth_code.code, oauth_request_list[i].client, oauth_request_list[i]) == (x == 0)
            assert (oauth_request_list[i].user == auth_code.user) == (x == 0)
            assert (oauth_request_list[i].scopes == auth_code.scopes) == (x == 0)
            assert oauth_request_list[i].claims is None

            reset_and_assert_empty(oauth_request_list[i])

            # Check for wrong client
            assert validator.validate_code('', auth_code.code, oauth_request_list[(i + 1) % 6].client, oauth_request_list[i]) == False
            assert oauth_request_list[i].user is None

            reset_and_assert_empty(oauth_request_list[i])

            auth = registry(AuthorizationCode).find(auth_code.id_)
            claims = {'data': 'not empty'}
            auth.claims = claims

            # Check claims is set on the request if exists on the auth code
            assert validator.validate_code('', auth_code.code, oauth_request_list[i].client, oauth_request_list[i]) == (x == 0)
            assert (oauth_request_list[i].user == auth_code.user) == (x == 0)
            assert (oauth_request_list[i].scopes == auth_code.scopes) == (x == 0)
            assert (oauth_request_list[i].claims == auth_code.claims) == (x == 0)

            reset_and_assert_empty(oauth_request_list[i])
            
            # Non-validated request should not set claims, scopes, user
            assert validator.validate_code('', 'fake_code', oauth_request_list[i].client, oauth_request_list[i]) == False
            assert_request_empty(oauth_request_list[i])

def assert_request_empty(request):
    assert request.claims is None
    assert request.user is None
    assert request.scopes is None

def reset_request(request):
    request.claims = None
    request.user = None
    request.scopes = None

def reset_and_assert_empty(request):
    reset_request(request)
    assert_request_empty(request)