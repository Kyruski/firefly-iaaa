from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
from firefly_iaaa.domain.entity.client import Client

from firefly_iaaa.domain.service.request_validator import OauthRequestValidators



def test_get_code_challenge_method(validator: OauthRequestValidators, oauth_request_list: List[Request], auth_codes_list: List[AuthorizationCode], client_list: List[Client]):
    for i in range(6):
        auth_code = auth_codes_list[i]['active']

        # Check it returns the correct challenge method
        assert validator.get_code_challenge_method(auth_code.code, oauth_request_list[i]) == auth_code.challenge_method

        # Check a non-existent code returns None
        assert validator.get_code_challenge_method('auth_code.code', oauth_request_list[i]) is None