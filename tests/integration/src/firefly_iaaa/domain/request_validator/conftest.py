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

import pytest
import firefly as ff
import firefly.infrastructure as ffi
from datetime import datetime, timedelta

import random

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator
from firefly_iaaa.infrastructure.service.oauth_endpoints import IamRequestValidator
from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.grant import Grant
from firefly_iaaa.domain.entity.role import Role
from firefly_iaaa.domain.entity.scope import Scope
from firefly_iaaa.domain.entity.tenant import Tenant
from firefly_iaaa.domain.entity.user import User
from oauthlib.common import Request


@pytest.fixture()
def auth_service(container, cache):
    validator = container.build(OauthlibRequestValidator)
    sut = container.build(IamRequestValidator, validator=validator)
    sut._cache = cache
    return sut

@pytest.fixture()
def cache(container):
    return container.build(MockCache)

@pytest.fixture()
def bearer_messages_list(message_factory, bearer_tokens_list: List[BearerToken], user_list: List[User], auth_codes_list: List[AuthorizationCode]):
    messages = []
    status = ['active', 'expired', 'invalid']
    for i in range(6):
        message_group = {}
        for x in range(3):
            bearer_token = bearer_tokens_list[i % 6][status[x]]
            auth_code = auth_codes_list[i % 6][status[x]]
            message = message_factory.query(
                name='a1b2c3',
                data={'headers': {'http_method': 'GET', 'uri': bearer_token.client.default_redirect_uri},
                    'username': user_list[i % 6].email,
                    'password': f'password{(i % 6) + 1}',
                    'grant_type': convert_grants(bearer_token.client.grant_type),
                    "access_token": bearer_token.access_token,
                    "client": None,
                    "client_id": bearer_token.client.client_id,
                    "client_secret": bearer_token.client.client_secret if i == 3 else None,
                    "code": auth_code.code,
                    "code_challenge": auth_code.challenge,
                    "code_challenge_method": None,
                    "code_verifier": auth_code.challenge,
                    "extra_credentials": None,
                    "redirect_uri": bearer_token.client.default_redirect_uri,
                    "refresh_token": bearer_token.refresh_token,
                    "request_token": None,
                    "response_type": bearer_token.client.allowed_response_types[0],
                    "scope": None,
                    "scopes": bearer_token.scopes,
                    "state": 'abc',
                    "token": bearer_token.refresh_token if (i % 3) == 0 else bearer_token.access_token if (i % 3) == 1 else None,
                    "user": None,
                    "token_type_hint": 'Bearer',
                    "credentials_key": None,
                }
            )
            message_group[status[x]] = message
        messages.append(message_group)
    return messages

@pytest.fixture()
def bearer_messages_second_list(message_factory, bearer_tokens_second_list: List[BearerToken], user_list: List[User], auth_codes_second_list: List[AuthorizationCode]):
    messages = []
    for i in range(25):
        bearer_token = bearer_tokens_second_list[i]
        auth_code = auth_codes_second_list[i]
        message = message_factory.query(
            name='a1b2c3',
            data={'headers': {'http_method': 'GET', 'uri': bearer_token.client.default_redirect_uri},
                'username': user_list[i % 6].email,
                'password': f'password{(i % 6) + 1}',
                'grant_type': convert_grants(bearer_token.client.grant_type),
                "access_token": bearer_token.access_token,
                "client": None,
                "client_id": bearer_token.client.client_id,
                "client_secret": bearer_token.client.client_secret,
                "code": auth_code.code,
                "code_challenge": auth_code.challenge,
                "code_challenge_method": auth_code.challenge_method,
                "code_verifier": auth_code.challenge,
                "extra_credentials": None,
                "redirect_uri": bearer_token.client.default_redirect_uri,
                "refresh_token": bearer_token.refresh_token,
                "request_token": None,
                "response_type": bearer_token.client.allowed_response_types[0],
                "scope": None,
                "scopes": bearer_token.scopes,
                "state": 'abc',
                "token": bearer_token.refresh_token if (i % 3) == 0 else bearer_token.access_token if (i % 3) == 1 else None,
                "user": None,
                "token_type_hint": 'Bearer',
                "credentials_key": None,
            }
        )
        messages.append(message)
    return messages


def convert_grants(grant):
    if grant == 'implicit':
        return 'refresh'
    return grant

@pytest.fixture()
def auth_codes_second_list(registry, client_list, user_list):
    codes = []
    for i in range(25):
        auth_code = AuthorizationCode(
            client=client_list[i % 6],
            user=user_list[6],
            scopes=client_list[i % 6].scopes,
            redirect_uri=client_list[i % 6].default_redirect_uri,
            code=f'{gen_random_string(34)}{i % 6}{1}',
            expires_at=datetime.utcnow() + timedelta(minutes=1),
            state='abc',
            challenge=f'{gen_random_string(126)}{i % 6}{1}',
            challenge_method=f'plain',
        )
        registry(AuthorizationCode).append(auth_code)
        codes.append(auth_code)
    return codes

@pytest.fixture()
def bearer_tokens_second_list(registry, client_list, user_list):
    tokens = []
    for i in range(25):
        bearer_token = BearerToken(
            client=client_list[i % 6],
            user=user_list[6],
            scopes=client_list[i % 6].scopes,
            access_token=f'{gen_random_string(34)}{i % 6}{1}',
            refresh_token=f'{i % 6}{1}{gen_random_string(34)}',
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


class MockCache(ff.Cache):
    _storage: dict = {}

    def set(self, key: str, value: Any, ttl: int = None, **kwargs):
        time = (datetime.now() + timedelta(seconds=ttl)) if ttl else None
        self._storage[key] = {'value': value, 'ttl': time}
    
    def get(self, key: str, **kwargs):
        item = self._storage.get(key)
        if not item:
            return None
        if item['ttl'] is None or datetime.now() < item['ttl']:
            return item['value']
        del self._storage[key]
        return None

    def delete(self, key: str, **kwargs):
        return None

    def clear(self, **kwargs):
        return None

    def increment(self, key: str, amount: int = 1, **kwargs) -> Any:
        return None

    def decrement(self, key: str, amount: int = 1, **kwargs) -> Any:
        return None

    def add(self, key: str, value: Any, **kwargs) -> Any:
        return None

    def remove(self, key: str, value: Any, **kwargs) -> Any:
        return None