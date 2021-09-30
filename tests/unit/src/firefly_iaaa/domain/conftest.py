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
import pytest
import bcrypt
import random

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator
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
def client_list(registry, user_list):
    users = []
    for user in user_list:
        registry(User).append(user)
        u = registry(User).find(user.sub)
        users.append(u)
    clients = make_client_list(users)
    for i, client in enumerate(clients):
        registry(Client).append(client)
        c = registry(Client).find(
            lambda x: (x.name == client.name)
        )
        users[i].client_id = c.client_id
    return clients

@pytest.fixture()
def validator(container):
    return container.build(OauthlibRequestValidator)

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
def user_list():
    string = gen_random_string()
    return [ User.create(email=f'user{i+1}{string}@fake.com', password=f'password{i + 1}') for i in range(8) ]

def hash_password(password: str, salt: str):
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def make_client_list(users):
    clients = []
    allowed_response_types = [['code'], ['token'], ['code', 'token'], ['token', 'code']]
    grant_types = ['Authorization Code', 'Implicit', 'Resource Owner Password Credentials', 'Client Credentials']
    for i in range(6):
        client = Client(
            user=users[i],
            name=f'client_{gen_random_string()}{i}',
            allowed_response_types=allowed_response_types[i % 4],
            default_redirect_uri=f'www.uri{i}.com',
            redirect_uris=[f'www.uri{i}.com', 'www.fake.com'],
            grant_type=grant_types[i % 4],
            uses_pkce=(i % 2 == 0 and i < 4),
            scopes=['fake scopes', f'faker scope{i}'],
            client_secret=gen_random_string(36),

        )
        clients.append(client)
    client = Client(
        user=users[i + 1],
        name=f'client_{gen_random_string()}{i + 1}',
        allowed_response_types=allowed_response_types[0],
        default_redirect_uri='www.uri0.com',
        redirect_uris=['www.uri0.com', 'www.fake.com'],
        grant_type=grant_types[0],
        uses_pkce=(1 % 2 == 0),
        scopes=['fake scopes', f'faker scope0'],
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
            auth_code = AuthorizationCode(
                client=client_list[i],
                user=user_list[6],
                scopes=client_list[i].scopes,
                redirect_uri=client_list[i].default_redirect_uri,
                code=f'{gen_random_string(34)}{i}{x}',
                expires_at=datetime.utcnow() if x == 1 else datetime.utcnow() + timedelta(minutes=1),
                state='abc',
                challenge=f'{gen_random_string(126)}{i}{x}',
                challenge_method=f'1234{i}{x}',
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
        auth_code = AuthorizationCode(
            client=client_list[-1],
            user=user_list[6],
            scopes=client_list[-1].scopes,
            redirect_uri=client_list[-1].default_redirect_uri,
            code=f'{gen_random_string(34)}{0}{x}',
            expires_at=datetime.utcnow() if x == 1 else datetime.utcnow() + timedelta(minutes=1),
            state='abc',
            challenge=f'{gen_random_string(126)}{0}{x}',
        challenge_method=f'1234{0}{x}',
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
def bearer_tokens_list(registry, client_list, user_list):
    tokens = []
    for i in range(6):
        token_group = {}
        for x in range(3):
            bearer_token = BearerToken(
                client=client_list[i],
                user=user_list[6],
                scopes=client_list[i].scopes,
                access_token=f'{gen_random_string(34)}{i}{x}',
                refresh_token=f'{i}{x}{gen_random_string(34)}',
                expires_at=datetime.utcnow() if x == 1 else datetime.utcnow() + timedelta(minutes=60),
            )
            if x == 2:
                bearer_token.is_valid = False
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
        bearer_token = BearerToken(
            client=client_list[-1],
            user=user_list[6],
            scopes=client_list[-1].scopes,
            access_token=f'{gen_random_string(34)}{0}{x}',
            refresh_token=f'{0}{x}{gen_random_string(34)}',
            expires_at=datetime.utcnow() if x == 1 else datetime.utcnow() + timedelta(minutes=60),
        )
        if x == 2:
            bearer_token.is_valid = False
        registry(BearerToken).append(bearer_token)
        if x == 0:
            token_group['active'] = bearer_token
        elif x == 1:
            token_group['expired'] = bearer_token
        else:
            token_group['invalid'] = bearer_token
    tokens.append(token_group)
    return tokens