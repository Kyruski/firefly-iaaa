from __future__ import annotations
from datetime import datetime, timedelta
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
import random
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User
from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator


def test_save_authorization_code(validator: OauthlibRequestValidator, oauth_request_list: List[Request], client_list: List[Client], user_list: List[User], registry):
    for i in range(4):
        code = {
            'code': gen_random_string(36),
            'expires_in': 3600,
            'scope': 'string of space separated authorized scopes',
            'refresh_code': gen_random_string(36),
            'state': 'given_by_client',
        }
        code_challenge = gen_random_string(128)
        code_challenge_method = gen_random_string(6)
        redirect_uri = gen_random_string(36)
        oauth_request_list[i].scopes = client_list[i].scopes
        oauth_request_list[i].user = user_list[i]
        oauth_request_list[i].redirect_uri = redirect_uri
        if i < 2:
            oauth_request_list[i].code_challenge = code_challenge
            oauth_request_list[i].code_challenge_method = code_challenge_method
        validator.save_authorization_code('', code, oauth_request_list[i])
        saved_code = registry(AuthorizationCode).find(lambda x: x.code == code['code'])
        assert saved_code.code == code['code']
        assert saved_code.scopes == client_list[i].scopes
        assert saved_code.redirect_uri == redirect_uri
        assert saved_code.user == user_list[i]
        assert saved_code.client == client_list[i]
        assert (datetime.utcnow() + timedelta(minutes=10)) - saved_code.expires_at < timedelta(seconds=1)
        if i < 2:
            assert saved_code.challenge == code_challenge
            assert saved_code.challenge_method == code_challenge_method


def gen_random_string(num: int = 6):
    alpha = 'abcdefghijklmnopqrstuvwxyz1234567890'
    string = ''
    for _ in range(num):
        string += alpha[random.randrange(0, 36)]
    return string
