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
from typing import List
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError

import pytest
import firefly as ff

from firefly_iaaa.infrastructure.service.oauth_endpoints import IamRequestValidator
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User
import json

def test_token_response(auth_service: IamRequestValidator, bearer_messages_list: List[ff.Message], bearer_tokens_list: List[BearerToken], user_list: List[User], client_list: List[Client]):

    VALID_METHOD_TYPES = ['GET', 'PUT', 'POST', 'DELETE', 'HEAD', 'PATCH']
    for i in range(6):
        for x in range(3):
            message_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
            message = bearer_messages_list[i][message_selector]
            message.headers['http_method'] = 'POST'
            headers, body, status = auth_service.create_token_response(message)

            is_true = ((x == 0 and i in (0, 4)) or (i in (2, 3)))
            body = json.loads(body)
            expected_status = 200 if is_true else 400
            assert status == expected_status
            assert (body.get('error') is None) == is_true

            assert (body.get('access_token') is None) != is_true

            assert (body.get('refresh_token') is None) != (is_true and i != 3)

            assert (body.get('expires_in') is None) != is_true
            assert (body.get('expires_in') == 3600) == is_true

            assert (body.get('token_type') is None) != is_true
            assert (body.get('token_type') == 'Bearer') == is_true

            assert (body.get('scope') is None) != is_true
            if is_true:
                assert body.get('scope') == ' '.join(bearer_tokens_list[i][message_selector].scopes)

    for method in VALID_METHOD_TYPES:
        if method == 'POST':
            continue
        message = bearer_messages_list[0]['active']
        message.headers['http_method'] = method
        with pytest.raises(InvalidRequestError):
            headers, body, status = auth_service.create_token_response(message)


def test_create_token_response_missing_data(auth_service: IamRequestValidator, bearer_messages_second_list: List[ff.Message]):

    message = bearer_messages_second_list[-1]
    message.headers['http_method'] = 'POST'

    headers, body, status = auth_service.create_token_response(message)
    body = json.loads(body)
    assert body.get('error') is None

    for i in range(16):
        message = bearer_messages_second_list[i]
        message.headers['http_method'] = 'POST'
        if i == 0:
            message.username = None
        if i == 1:
            message.password = None
        if i == 2:
            message.grant_type = None
        if i == 3:
            message.access_token = None
        if i == 4:
            message.client_id = None
        if i == 5:
            message.client_secret = None
        if i == 6:
            message.code = None
        if i == 7:
            message.code_challenge = None
        if i == 8:
            message.code_challenge_method = None
        if i == 9:
            message.code_verifier = None
        if i == 10:
            message.redirect_uri = None
        if i == 11:
            message.refresh_token = None
        if i == 12:
            message.response_type = None
        if i == 13:
            message.scopes = None
        if i == 14:
            message.state = None
        if i == 15:
            message.token_type_hint = None

        headers, body, status = auth_service.create_token_response(message)
        body = json.loads(body)
        assert (body.get('error') is None) == (i in (0, 3, 4, 8, 9, 10, 12, 14, 15))
