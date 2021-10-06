from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator



def test_confirm_redirect_uri(validator: OauthlibRequestValidator, oauth_request_list: List[Request], auth_codes_list: List[AuthorizationCode]):
    for i in range(6):
        auth_code = auth_codes_list[i]['active']
        assert validator.confirm_redirect_uri('', auth_code.code, auth_code.redirect_uri, oauth_request_list[i].client, oauth_request_list[i]) == True
        assert validator.confirm_redirect_uri('', auth_code.code, 'auth_code.redirect_uri', oauth_request_list[i].client, oauth_request_list[i]) == False
        assert validator.confirm_redirect_uri('', auth_code.code, None, oauth_request_list[i].client, oauth_request_list[i]) == False
        assert validator.confirm_redirect_uri('', '111', auth_code.redirect_uri, oauth_request_list[i].client, oauth_request_list[i]) == False
