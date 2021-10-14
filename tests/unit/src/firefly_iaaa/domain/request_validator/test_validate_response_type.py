from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.infrastructure.service.request_validator import OauthRequestValidators


def test_validate_response_type(validator: OauthRequestValidators, oauth_request_list: List[Request]):
    allowed_response_types = [['code'], ['token'], ['code', 'token'], ['token', 'code']]
    for i in range(6):
        assert validator.validate_response_type('', 'code', oauth_request_list[i].client, oauth_request_list[i]) == ('code' in allowed_response_types[i % 4])
        assert validator.validate_response_type('', 'token', oauth_request_list[i].client, oauth_request_list[i]) == ('token' in allowed_response_types[i % 4])
        assert validator.validate_response_type('', 'id_token', oauth_request_list[i].client, oauth_request_list[i]) == False

