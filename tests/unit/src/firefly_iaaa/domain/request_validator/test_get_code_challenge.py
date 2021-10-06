from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
from firefly_iaaa.domain.entity.client import Client

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator



def test_get_code_challenge(validator: OauthlibRequestValidator, oauth_request_list: List[Request], auth_codes_list: List[AuthorizationCode], client_list: List[Client]):
    for i in range(6):
        auth_code = auth_codes_list[i]['active']
        assert validator.get_code_challenge(auth_code.code, oauth_request_list[i]) == auth_code.challenge
        assert validator.get_code_challenge('auth_code.code', oauth_request_list[i]) is None