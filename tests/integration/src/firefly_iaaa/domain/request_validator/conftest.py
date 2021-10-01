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

import pytest
import firefly as ff
import firefly.infrastructure as ffi

import random
import bcrypt

from firefly_iaaa.infrastructure.service.request_validator import *
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
def auth_service(container):
    validator = container.build(OauthlibRequestValidator)
    return container.build(IamRequestValidator, validator=validator)

@pytest.fixture()
def bearer_messages_list(message_factory, bearer_tokens_list: List[BearerToken], user_list: List[User], auth_codes_list: List[AuthorizationCode]):
    messages = []
    VALID_METHOD_TYPES = ['GET', 'PUT', 'POST', 'DELETE', 'HEAD', 'PATCH']
    status = ['active', 'expired', 'invalid']
    for i in range(6):
        message_group = {}
        for x in range(3):
            nested_messages = {}
            for y in range(6):
                bearer_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
                bearer_token = bearer_tokens_list[i][bearer_selector]
                auth_code = auth_codes_list[i][bearer_selector]
                message = message_factory.query(
                    name='a1b2c3',
                    data={'headers': {'http_method': VALID_METHOD_TYPES[y], 'uri': 'https://app.pwrlab.com'},
                        'username': user_list[i].email if i % 2 == 0 else None,
                        'password': f'password{i + 1}',
                        'grant_type': convert_grants(bearer_token.client.grant_type),
                        "access_token": bearer_token.access_token,
                        "client": None,
                        "client_id": bearer_token.client.client_id,
                        "client_secret": bearer_token.client.client_secret if i == 3 else None,
                        "code": auth_code.code,
                        "code_challenge": None,
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
                        "token": None,
                        "user": None,
                        "token_type_hint": 'Bearer',
                    }
                )
                nested_messages[VALID_METHOD_TYPES[y]] = message
            message_group[status[x]] = nested_messages
        messages.append(message_group)
    return messages


def convert_grants(grant):
    if grant == 'implicit':
        return 'refresh'
    return grant
