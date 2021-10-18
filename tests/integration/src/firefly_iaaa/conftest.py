#  Copyright (c) 2019 JD Williams
#
#  This file is part of Firefly, a Python SOA framework built by JD Williams. Firefly is free software; you can
#  redistribute it and/or modify it under the terms of the GNU General Public License as published by the
#  Free Software Foundation; either version 3 of the License, or (at your option) any later version.
#
#  Firefly is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
#  Public License for more details. You should have received a copy of the GNU Lesser General Public
#  License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  You should have received a copy of the GNU General Public License along with Firefly. If not, see
#  <http://www.gnu.org/licenses/>.
from __future__ import annotations
from typing import Any, List
import uuid
import jwt
import hashlib
import os
import re
from base64 import urlsafe_b64encode

import pytest
import firefly as ff
from datetime import datetime, timedelta

import random

from firefly_iaaa.domain.service.request_validator import OauthRequestValidators
from firefly_iaaa.domain.service.oauth_provider import OauthProvider
from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.user import User
from firefly_iaaa.domain.mock.mock_cache import MockCache


@pytest.fixture()
def auth_service(container, cache, secret, issuer):
    validator = container.build(OauthRequestValidators)
    validator._secret_key = secret
    sut = container.build(OauthProvider, validator=validator)
    sut._cache = cache
    sut._secret_key = secret
    sut._issuer = issuer
    return sut

def generate_token(request, token_type, issuer, secret):
    token_info = {
        'jti': str(uuid.uuid4()),
        'aud': request['client_id'],
        'iss': issuer,
        'scope': ' '.join(request['scopes'])
    }
    if token_type == 'access_token':
        token_info['exp'] = datetime.utcnow() + timedelta(seconds=request['expires_in'])
    token = jwt.encode(token_info, secret, algorithm='HS256')
    return token

@pytest.fixture()
def cache(container):
    return container.build(MockCache)

@pytest.fixture()
def bearer_messages_second_list(message_factory, bearer_tokens_second_list: List[BearerToken], user_list: List[User], auth_codes_second_list: List[AuthorizationCode]):
    messages = []
    for i in range(19):
        bearer_token = bearer_tokens_second_list[i]
        auth_code = auth_codes_second_list[i]
        message = message_factory.query(
            name='a1b2c3',
            data={'headers': {'http_method': 'GET', 'uri': bearer_token.client.default_redirect_uri},
                'username': user_list[i % 6].email,
                'password': f'password{(i % 6) + 1}',
                'grant_type': bearer_token.client.grant_type,
                'access_token': bearer_token.access_token,
                'client': None,
                'client_id': bearer_token.client.client_id,
                'client_secret': bearer_token.client.client_secret,
                'code': auth_code.code,
                'code_challenge': auth_code.challenge,
                'code_challenge_method': auth_code.challenge_method,
                'code_verifier': auth_code.verifier,
                'extra_credentials': None,
                'redirect_uri': bearer_token.client.default_redirect_uri,
                'refresh_token': bearer_token.refresh_token,
                'request_token': None,
                'response_type': bearer_token.client.allowed_response_types[0],
                'scope': None,
                'scopes': bearer_token.scopes,
                'state': 'abc',
                'token': bearer_token.refresh_token if (i % 3) == 0 else bearer_token.access_token if (i % 3) == 1 else None,
                'user': None,
                'token_type_hint': 'Bearer',
                'credentials_key': None,
            }
        )
        messages.append(message)
    return messages


def generate_code_challenge():
    code_verifier = ''
    code_verifier = urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

    code_challenge = urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    code_challenge_method = 'S256'
    return {
        'code_verifier': code_verifier,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method
    }

@pytest.fixture()
def auth_codes_second_list(registry, client_list, user_list):
    codes = []
    for i in range(19):
        code_challenge = generate_code_challenge()
        auth_code = AuthorizationCode(
            client=client_list[i % 6],
            user=user_list[6],
            scopes=client_list[i % 6].scopes,
            redirect_uri=client_list[i % 6].default_redirect_uri,
            code=f'{gen_random_string(34)}{i % 6}{1}',
            expires_at=datetime.utcnow() + timedelta(minutes=1),
            state='abc',
            challenge=code_challenge['code_challenge'],
            challenge_method=code_challenge['code_challenge_method'],
            verifier=code_challenge['code_verifier'],
        )
        registry(AuthorizationCode).append(auth_code)
        codes.append(auth_code)
    return codes

@pytest.fixture()
def bearer_tokens_second_list(registry, client_list, user_list, issuer, secret):
    tokens = []
    for i in range(19):
        token_info = {
            'client_id': client_list[i % 6].client_id,
            'expires_in': 3600,
            'scopes': client_list[i % 6].scopes,
        }
        bearer_token = BearerToken(
            client=client_list[i % 6],
            user=user_list[-2],
            scopes=client_list[i % 6].scopes,
            access_token=generate_token(token_info, 'access_token', issuer, secret),
            refresh_token=generate_token(token_info, 'refresh_token', issuer, secret),
            expires_at=datetime.utcnow() + timedelta(minutes=60),
        )
        registry(BearerToken).append(bearer_token)
        tokens.append(bearer_token)
    return tokens

def gen_random_string(num: int = 6):
    alpha = 'abcdefghijklmnopqrstuvwxyz1234567890'
    string = ''
    for _ in range(num):
        string += alpha[random.randrange(0, 36)]
    return string
