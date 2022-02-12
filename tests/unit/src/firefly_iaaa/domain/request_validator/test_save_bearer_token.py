from __future__ import annotations
from datetime import datetime, timedelta
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.bearer_token import BearerToken
import random
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User
from firefly_iaaa.domain.entity.scope import Scope
from firefly_iaaa.domain.service.request_validator import OauthRequestValidators


def test_save_bearer_token(validator: OauthRequestValidators, oauth_request_list: List[Request], client_list: List[Client], user_list: List[User], registry):
    scopes = [Scope('string'), Scope('of'), Scope('space'), Scope('separated'), Scope('authorized'), Scope('scopes')]
    for s in scopes:
        registry(Scope).append(s)
    for i in range(4):
        token = {
            'token_type': 'Bearer',
            'access_token': gen_random_string(36),
            'expires_in': 3600,
            'scope': 'string of space separated authorized scopes',
            'refresh_token': gen_random_string(36),
            'state': 'given_by_client',
        }

        oauth_request_list[i].scopes = token['scope'].split(' ')
        oauth_request_list[i].user = user_list[i]

        # Check the returned redirect uri is correct
        assert validator.save_bearer_token(token, oauth_request_list[i]) == client_list[i].default_redirect_uri
        saved_token = registry(BearerToken).find(lambda x: x.refresh_token == token['refresh_token'])
        saved_time = datetime.utcnow()

        #Check the saved token exists
        assert saved_token.token_type == token['token_type']
        assert saved_token.access_token == token['access_token']

        scopes = token['scope'].split(' ')
        assert len(saved_token.scopes) == len(scopes)
        for s in saved_token.scopes:
            assert s.id in scopes
        assert saved_token.access_token == token['access_token']
        assert saved_token.user == user_list[i]
        assert saved_token.client == client_list[i]
        assert (saved_time + timedelta(seconds=token['expires_in'])) - saved_token.expires_at < timedelta(seconds=5)

def gen_random_string(num: int = 6):
    alpha = 'abcdefghijklmnopqrstuvwxyz1234567890'
    string = ''
    for _ in range(num):
        string += alpha[random.randrange(0, 36)]
    return string
