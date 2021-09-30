from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator


def test_validate_code(validator: OauthlibRequestValidator, oauth_request_list: List[Request], auth_codes_list: List[AuthorizationCode], registry):
    for i in range(6):
        for x in range(3):
            code_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
            auth_code = auth_codes_list[i][code_selector]
            assert_request_empty(oauth_request_list[i])
            assert validator.validate_code('', auth_code.code, oauth_request_list[i].client, oauth_request_list[i]) == (x == 0)
            assert (oauth_request_list[i].user == auth_code.user) == (x == 0)
            assert (oauth_request_list[i].scopes == auth_code.scopes) == (x == 0)
            assert oauth_request_list[i].claims is None

            reset_request(oauth_request_list[i])
            assert_request_empty(oauth_request_list[i])

            assert validator.validate_code('', auth_code.code, oauth_request_list[(i + 1) % 6].client, oauth_request_list[i]) == False #Check for wrong client
            assert oauth_request_list[i].user is None

            reset_request(oauth_request_list[i])
            assert_request_empty(oauth_request_list[i])

            auth = registry(AuthorizationCode).find(auth_code.id_)
            auth.claims = {'data': 'not empty'}

            assert validator.validate_code('', auth_code.code, oauth_request_list[i].client, oauth_request_list[i]) == (x == 0)
            assert (oauth_request_list[i].user == auth_code.user) == (x == 0)
            assert (oauth_request_list[i].scopes == auth_code.scopes) == (x == 0)
            assert (oauth_request_list[i].claims is not None) == (x == 0)

            reset_request(oauth_request_list[i])
            assert_request_empty(oauth_request_list[i])

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