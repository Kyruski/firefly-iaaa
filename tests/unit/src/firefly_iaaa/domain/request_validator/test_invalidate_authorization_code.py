from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode

from firefly_iaaa.infrastructure.service.request_validator import OauthRequestValidators


def test_invalidate_authorization_code(validator: OauthRequestValidators, oauth_request_list: List[Request], auth_codes_list: List[AuthorizationCode], registry):
    token_status = ['active', 'expired', 'invalid']
    for i in range(6):
        for x in range(3):
            current_token_type = token_status[x]
            auth_code = auth_codes_list[i][current_token_type]

            # Check both string and dictionary work
            if i < 3:
                code = auth_code.code
            else:
                code = { 'code': auth_code.code }
            found_auth_code = registry(AuthorizationCode).find(lambda x: x.code == auth_code.code)

            # Check if the code is valid (when x == 2, the coe is always invalid)
            assert found_auth_code.is_valid == (x != 2)

            # Try invalidating with wrong code, check still valid
            validator.invalidate_authorization_code('', 'code', oauth_request_list[i])
            assert found_auth_code.is_valid == (x != 2)

            # Invalidate with correct code, should be invalid
            validator.invalidate_authorization_code('', code, oauth_request_list[i])
            assert found_auth_code.is_valid == False
        
            #Checking to make sure it's not affecting other codes
            next_auth_code = registry(AuthorizationCode).find(lambda x: x.code == auth_codes_list[i + 1][current_token_type].code)
            assert next_auth_code.is_valid == (x != 2)
