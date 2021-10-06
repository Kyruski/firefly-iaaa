from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator


def test_validate_grant_type(validator: OauthlibRequestValidator, oauth_request_list: List[Request]):
    grant_types = ['authorization_code', 'implicit', 'password', 'client_credentials']
    for i in range(6):
        for x in range(4):
            assert validator.validate_grant_type('', grant_types[x], oauth_request_list[i].client, oauth_request_list[i]) == ((i % 4) == x)
            assert validator.validate_grant_type('', grant_types[(x + 1) % 4], oauth_request_list[i].client, oauth_request_list[i]) == ((i % 4) == (x + 1) % 4)
