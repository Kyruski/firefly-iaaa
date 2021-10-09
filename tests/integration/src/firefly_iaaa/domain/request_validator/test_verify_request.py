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

from firefly_iaaa.infrastructure.service.oauth_endpoints import OauthRequestValidator
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User

def test_verify_request(auth_service: OauthRequestValidator, bearer_messages_list: List[ff.Message], bearer_tokens_list: List[BearerToken], user_list: List[User], client_list: List[Client]):

    token_status = ['active', 'expired', 'invalid']
    for i in range(6):
        for x in range(3):
            message = bearer_messages_list[i][token_status[x]]

            # Check with different scopes (y == 0 uses correct scopes, y == 1 uses incorrect scopes)
            for y in range(2):
                scopes = message.scopes if y == 0 else ['aaa', 'bbb']
                validated, resp = auth_service.verify_request(message, scopes)

                # is_true is valid if token_status is 'active' and scopes are correct
                is_true = ((x == 0) and y == 0)
                assert validated == is_true

                if is_true:
                    # If it's supposed to be valid, check the resp contains the correct user, client, and scopes
                    assert resp.user['sub'] == user_list[-2].sub
                    assert resp.client['client_id'] == client_list[i].client_id
                    assert resp.scopes == scopes
                else:
                    # If invalid, check user and client is none, while scoeps (set earlier) is scopes
                    assert resp.user is None
                    assert resp.client is None
                    assert resp.scopes == scopes

def test_verify_request_missing_data(auth_service: OauthRequestValidator, bearer_messages_second_list: List[ff.Message]):

    message = bearer_messages_second_list[-1]
    validated, resp = auth_service.verify_request(message, message.scopes)
    assert validated


    # Check for various missing attributes from message
    for i in range(16):
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
            # Missing scopes should error out
            message.scopes = None
            with pytest.raises(TypeError):
                validated, resp = auth_service.verify_request(message, message.scopes)
            continue
        if i == 14:
            message.state = None
        if i == 15:
            message.token_type_hint = None

        # Should validate to True if it's not missing an access token 
        validated, resp = auth_service.verify_request(message, message.scopes)
        assert validated == (i != 3)
