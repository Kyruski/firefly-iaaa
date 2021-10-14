from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.infrastructure.service.request_validator import OauthRequestValidators


def test_validate_scopes(validator: OauthRequestValidators, oauth_request_list: List[Request]):
    scopes = ['fake-scopes', 'faker-scope']
    for i in range(6):
        # Should validate scopes
        assert validator.validate_scopes('', [scopes[0], f'{scopes[1]}{i}'], oauth_request_list[i].client, oauth_request_list[i]) == True

        # Should not validate extra scopes
        assert validator.validate_scopes('', [*scopes, 'abc'], oauth_request_list[i].client, oauth_request_list[i]) == False
        assert validator.validate_scopes('', ['fake_scopes', f'faker_scope{i + 1}'], oauth_request_list[i].client, oauth_request_list[i]) == False
