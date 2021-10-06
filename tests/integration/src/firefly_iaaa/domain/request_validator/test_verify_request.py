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

import pytest
import firefly as ff

from firefly_iaaa.infrastructure.service.oauth_endpoints import IamRequestValidator
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User

def test_verify_request(auth_service: IamRequestValidator, bearer_messages_list: List[ff.Message], bearer_tokens_list: List[BearerToken], user_list: List[User], client_list: List[Client]):

    for i in range(6):
        for x in range(3):
            for y in range(2):
                message_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
                message = bearer_messages_list[i][message_selector]
                scopes = bearer_tokens_list[i][message_selector].scopes if y == 0 else ['aaa', 'bbb']
                validated, resp = auth_service.verify_request(message, scopes)
                is_true = ((x == 0) and y == 0)
                assert validated == is_true

                if is_true:
                    assert resp.user['sub'] == user_list[-2].sub if is_true else None
                    assert resp.client['client_id'] == client_list[i].client_id if is_true else None
                    assert resp.scopes == scopes
                else:
                    assert resp.user is None
                    assert resp.client is None
                    assert resp.scopes == scopes

def test_verify_request_missing_data(auth_service: IamRequestValidator, bearer_messages_second_list: List[ff.Message]):

    message = bearer_messages_second_list[-1]
    validated, resp = auth_service.verify_request(message, message.scopes)
    assert validated

    for i in range(14):
        message = bearer_messages_second_list[i]
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
            with pytest.raises(TypeError):
                validated, resp = auth_service.verify_request(message, message.scopes)
            continue
        if i == 14:
            message.state = None
        if i == 15:
            message.token_type_hint = None

        validated, resp = auth_service.verify_request(message, message.scopes)
        assert (validated == True) == (i != 3)

        if i in (0, 1, 2, 4):
            assert validated == True
