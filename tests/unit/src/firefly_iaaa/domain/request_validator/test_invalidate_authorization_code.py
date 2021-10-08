from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidators


def test_invalidate_authorization_code(validator: OauthlibRequestValidators, oauth_request_list: List[Request], auth_codes_list: List[AuthorizationCode], registry):
    for i in range(6):
        for x in range(3):
            code_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
            auth_code = auth_codes_list[i][code_selector]
            if i < 3:
                code = auth_code.code
            else:
                code = { 'code': auth_code.code }
            found_auth_code = registry(AuthorizationCode).find(lambda x: x.code == auth_code.code)
            assert found_auth_code.is_valid == (x != 2)
            validator.invalidate_authorization_code('', 'code', oauth_request_list[i])
            assert found_auth_code.is_valid == (x != 2)
            validator.invalidate_authorization_code('', code, oauth_request_list[i])
            assert found_auth_code.is_valid == False
        
            #Checking to make sure it's not affecting other codes
            next_auth_code = registry(AuthorizationCode).find(lambda x: x.code == auth_codes_list[i + 1][code_selector].code)
            assert next_auth_code.is_valid == (x != 2)
