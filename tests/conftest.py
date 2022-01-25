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

from datetime import datetime, timedelta
from typing import List
import uuid
import hashlib
import re
import os
import base64
from base64 import urlsafe_b64encode
from firefly import domain

import jwt
import pytest
import bcrypt
import random

from firefly_iaaa.domain.service.oauth_provider import OauthProvider
from firefly_iaaa.domain.service.request_validator import OauthRequestValidators
from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.role import Role
from firefly_iaaa.domain.entity.scope import Scope
from firefly_iaaa.domain.entity.tenant import Tenant
from firefly_iaaa.domain.entity.user import User
from oauthlib.common import Request
from firefly_iaaa.domain.mock import MockCache

from dotenv import load_dotenv


@pytest.fixture(scope="session")
def config():
    load_dotenv()
    os.environ['CONTEXT'] = 'firefly_iaaa'
    return {
        'contexts': {
            'firefly_iaaa': {
                'storage': {
                    'services': {
                        'rdb': {
                            'connection': {
                                'driver': 'sqlite',
                                'host': ':memory:'
                                # 'host': '/tmp/todo.db'
                            }
                        },
                    },
                    'default': 'rdb',
                },
            },
        },
    }

@pytest.fixture(autouse=True)
def set_kernel_user(container):
    container.kernel.user = domain.User(
        id='abc123',
        scopes=['fake-scopes'],
        tenant='tenant-id'
    )


@pytest.fixture()
def scopes(registry):
    scopes_dict = {
        'fake_scopes': [Scope(id='fake-scopes')]
    }
    for i in range(10):
        scopes_dict[f'faker_scope{i}'] = [Scope(id=f'faker-scope{i}')]
    for s in scopes_dict.values():
        registry(Scope).append(s)
    return scopes_dict

@pytest.fixture()
def roles(scopes, registry):
    roles_dict = {
        'client_role': [Role(name='client_role', scopes=scopes['fake_scopes'])],
        'user_role': [Role(name='user_role', scopes=scopes['fake_scopes'])]
    }
    for r in roles_dict.values():
        registry(Role).append(r)
    return roles_dict

@pytest.fixture()
def bearer_messages(bearer_messages_list, registry):
    print('9876', bearer_messages_list)
    print('666666')
    registry(BearerToken).commit()
    registry(AuthorizationCode).commit()
    return bearer_messages_list

@pytest.fixture()
def auth_service(container, cache, secret, issuer):
    validator = container.build(OauthRequestValidators)
    validator._secret_key = secret
    sut = container.build(OauthProvider, validator=validator)
    sut._cache = cache
    sut._secret_key = secret
    sut._issuer = issuer
    return sut

@pytest.fixture()
def secret():
    return str(base64.b64decode(os.environ['TEST_PEM']), "utf-8")

@pytest.fixture()
def issuer():
    return os.environ['ISSUER']

def generate_token(request, token_type, issuer, secret):
    token_info = {
        'jti': str(uuid.uuid4()),
        'aud': request['client_id'],
        'iss': issuer,
        'scope': ' '.join([s.id for s in request['scopes']])
    }
    if token_type == 'access_token':
        token_info['exp'] = datetime.utcnow() + timedelta(seconds=request['expires_in'])
    token = jwt.encode(token_info, secret, algorithm='HS256')
    return token

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
def client_list(registry, user_list, tenants_list, roles, scopes):
    clients = make_client_list(tenants_list, roles, scopes)
    for i, client in enumerate(clients):
        registry(User).append(user_list[i])
        registry(Client).append(client)
    registry(User).append(user_list[-1])
    registry(Role).commit()
    registry(Scope).commit()
    registry(User).commit()
    registry(Client).commit()
    registry(Tenant).commit()
    return clients

@pytest.fixture()
def tenants_list(registry):
    tenants = []
    for i in range(9):
        tenant = Tenant(name=f'tenant{i}')
        tenants.append(tenant)
        registry(Tenant).append(tenant)
    return tenants

@pytest.fixture()
def oauth_request_list(client_list):
    request_list = []
    for i in range(7):
        request = Request(uri='a:y:x',http_method='GET', body={'x': True}, headers=None)
        request.client = client_list[i]
        request_list.append(request)
    request_list.append(Request(uri='a:y:x',http_method='GET', body={'x': True}, headers=None))
    return request_list

def gen_random_string(num: int = 6):
    alpha = 'abcdefghijklmnopqrstuvwxyz1234567890'
    string = ''
    for _ in range(num):
        string += alpha[random.randrange(0, 36)]
    return string

@pytest.fixture()
def user_list(tenants_list):
    string = gen_random_string()
    array = [ User.create(email=f'user{i+1}{string}@fake.com', password=f'password{i + 1}', tenant=tenants_list[i]) for i in range(6) ]
    for i in range(6, 9):
        array.append(User.create(email=f'user{i+1}{string}@fake.com', password=f'password{i + 1}', tenant=tenants_list[i]))
    print('uuii', array)
    return array

def hash_password(password: str, salt: str):
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def make_client_list(tenants, roles, scopes):
    clients = []
    allowed_response_types = [['code'], ['token'], ['code', 'token'], ['token', 'code']]
    grant_types = ['authorization_code', 'refresh_token', 'password', 'client_credentials']
    for i in range(6):
        client = Client.create(
            tenant=tenants[i],
            name=f'client_{gen_random_string()}{i}',
            allowed_response_types=allowed_response_types[i % 4],
            default_redirect_uri=f'https://www.uri{i}.com',
            redirect_uris=[f'https://www.uri{i}.com', 'https://www.fake.com'],
            grant_type=grant_types[i % 4],
            uses_pkce=(i % 2 == 0 and i < 4),
            scopes=scopes[f'faker_scope{i}'],
            roles=roles['client_role'],
            client_secret=gen_random_string(36),
        )
        clients.append(client)
    client = Client.create(
        tenant=tenants[i + 1],
        name=f'client_{gen_random_string()}{i + 1}',
        allowed_response_types=allowed_response_types[0],
        default_redirect_uri='https://www.uri0.com',
        redirect_uris=['https://www.uri0.com', 'https://www.fake.com'],
        grant_type=grant_types[0],
        uses_pkce=False,
        scopes=scopes[f'faker_scope0'],
        roles=roles['client_role'],
        client_secret=gen_random_string(36),
    )
    clients.append(client)

    return clients

@pytest.fixture()
def auth_codes_list(registry, client_list, user_list):
    codes = []
    for i in range(6):
        code_group = {}
        for x in range(3):
            code_challenge = generate_code_challenge()
            auth_code = AuthorizationCode(
                client=client_list[i % 6],
                user=user_list[6],
                scopes=client_list[i % 6]._get_entity_scopes(),
                redirect_uri=client_list[i % 6].default_redirect_uri,
                code=f'{gen_random_string(34)}{i % 6}{x}',
                expires_at=datetime.utcnow() if x == 1 else datetime.utcnow() + timedelta(minutes=1),
                state='abc',
                challenge=code_challenge['code_challenge'],
                challenge_method=code_challenge['code_challenge_method'],
                verifier=code_challenge['code_verifier'],
            )
            if x == 2:
                auth_code.is_valid = False
            registry(AuthorizationCode).append(auth_code)
            if x == 0:
                code_group['active'] = auth_code
            elif x == 1:
                code_group['expired'] = auth_code
            else:
                code_group['invalid'] = auth_code
        codes.append(code_group)

    code_group = {}
    for x in range(3):
        code_challenge = generate_code_challenge()
        auth_code = AuthorizationCode(
            client=client_list[-1],
            user=user_list[6],
            scopes=client_list[-1]._get_entity_scopes(),
            redirect_uri=client_list[-1].default_redirect_uri,
            code=f'{gen_random_string(34)}{0}{x}',
            expires_at=datetime.utcnow() if x == 1 else datetime.utcnow() + timedelta(minutes=1),
            state='abc',
            challenge=code_challenge['code_challenge'],
            challenge_method=code_challenge['code_challenge_method'],
            verifier=code_challenge['code_verifier'],
        )
        if x == 2:
            auth_code.is_valid = False
        registry(AuthorizationCode).append(auth_code)
        if x == 0:
            code_group['active'] = auth_code
        elif x == 1:
            code_group['expired'] = auth_code
        else:
            code_group['invalid'] = auth_code
    codes.append(code_group)
    return codes

@pytest.fixture()
def bearer_tokens_list(registry, client_list, user_list, issuer, secret):
    tokens = []
    for i in range(6):
        token_group = {}
        for x in range(3):
            token_info = {
                'client_id': client_list[i].client_id,
                'expires_in': 3600,
                'scopes': client_list[i]._get_entity_scopes(),
            }
            print('999999', user_list[-2])
            bearer_token = BearerToken(
                client=client_list[i],
                user=user_list[-2],
                scopes=client_list[i]._get_entity_scopes(),
                access_token=generate_token(token_info, 'access_token', issuer, secret),
                refresh_token=generate_token(token_info, 'refresh_token', issuer, secret),
                expires_at=datetime.utcnow() if x == 1 else datetime.utcnow() + timedelta(minutes=60),
            )
            if x == 2:
                bearer_token.invalidate()
            registry(BearerToken).append(bearer_token)
            if x == 0:
                token_group['active'] = bearer_token
            elif x == 1:
                token_group['expired'] = bearer_token
            else:
                token_group['invalid'] = bearer_token
        tokens.append(token_group)

    token_group = {}
    for x in range(3):
        token_info = {
            'client_id': client_list[-1].client_id,
            'expires_in': 3600,
            'scopes': client_list[-1]._get_entity_scopes(),
        }
        print('999999', user_list[-2])
        bearer_token = BearerToken(
            client=client_list[-1],
            user=user_list[-2],
            scopes=client_list[-1]._get_entity_scopes(),
            access_token=generate_token(token_info, 'access_token', issuer, secret),
            refresh_token=generate_token(token_info, 'refresh_token', issuer, secret),
            expires_at=datetime.utcnow() if x == 1 else datetime.utcnow() + timedelta(minutes=60),
        )
        if x == 2:
            bearer_token.invalidate()
        registry(BearerToken).append(bearer_token)
        if x == 0:
            token_group['active'] = bearer_token
        elif x == 1:
            token_group['expired'] = bearer_token
        else:
            token_group['invalid'] = bearer_token
    tokens.append(token_group)
    return tokens


@pytest.fixture()
def cache(container):
    return container.build(MockCache)

@pytest.fixture()
def bearer_messages_list(message_factory, bearer_tokens_list: List[dict], user_list: List[User], auth_codes_list: List[AuthorizationCode]):
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
                    'grant_type': bearer_token.client.grant_type,
                    'access_token': bearer_token.access_token,
                    'client': None,
                    'client_id': bearer_token.client.client_id,
                    'client_secret': bearer_token.client.client_secret if i == 3 else None,
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
                    'scopes': bearer_token.get_scopes(),
                    'state': 'abc',
                    'token': bearer_token.refresh_token if (i % 3) == 0 else bearer_token.access_token if (i % 3) == 1 else None,
                    'email': bearer_token.user.email,
                    'user': None,
                    'token_type_hint': 'Bearer',
                    'credentials_key': None,
                }
            )
            message_group[status[x]] = message
        messages.append(message_group)
    return messages