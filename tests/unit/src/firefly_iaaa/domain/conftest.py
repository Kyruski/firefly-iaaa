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

import firefly as ff
import firefly.infrastructure as ffi
import pytest
import bcrypt

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
    for client in clients:
        registry(Client).append(client)
    return clients

@pytest.fixture()
def validator(container):
    return container.build(OauthlibRequestValidator)

@pytest.fixture()
def oauth_request_list(client_list):
    request_list = []
    for i in range(4):
        request = Request(uri='a:y:x',http_method='GET', body={'x': True}, headers=None)
        request.client = client_list[i]
        request_list.append(request)
    request_list.append(Request(uri='a:y:x',http_method='GET', body={'x': True}, headers=None))
    return request_list

@pytest.fixture()
def user_list():
    emails = ['user1@fake.com', 'user2@fake.com', 'user3@fake.com', 'user4@fake.com', 'user5@fake.com']
    passwords = ['password1', 'password2', 'password3', 'password4', 'password5']
    salt = bcrypt.gensalt()
    return [ User(email=emails[i], password_hash=hash_password(passwords[i], salt=salt)) for i in range(len(emails)) ]

def hash_password(password: str, salt: str):
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def make_client_list(users):
    clients = []
    allowed_response_types = [['code'], ['token'], ['code', 'token'], ['token', 'code']]
    grant_types = ['Authorization Code', 'Implicit', 'Resource Owner Password Credentials', 'Client Credentials']
    redirect_uris = ['www.uri0.com', 'www.uri1.com', 'www.uri2.com', 'www.uri3.com', ]
    for i in range(4):
        client = Client(
            user=users[i],
            name=f'client_{i}',
            allowed_response_types=allowed_response_types[i],
            default_redirect_uri=redirect_uris[i],
            grant_type=grant_types[i],
            scopes=['fake scopes', f'faker scope{i}'],

        )
        clients.append(client)
    return clients