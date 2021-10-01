from __future__ import annotations
from typing import List
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User
import firefly as ff
import json

from firefly_iaaa.infrastructure.service.request_validator import IamRequestValidator

def test_token_response(bearer_messages_list: List[ff.Message], auth_service: IamRequestValidator, bearer_tokens_list: List[BearerToken], user_list: List[User], client_list: List[Client]):

    VALID_METHOD_TYPES = ['GET', 'PUT', 'POST', 'DELETE', 'HEAD', 'PATCH']
    for i in range(6):
        for x in range(3):
            message_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
            message = bearer_messages_list[i][message_selector][VALID_METHOD_TYPES[2]]
            print(f'abcbcabcbabcabcbabcba, {i}{x}', message.grant_type)
            headers, body, status = auth_service.create_token_response(message)

            is_true = ((x == 0 and i in (0, 2, 3, 4)) or (i in (2, 3)))

            body = json.loads(body)
            print(is_true, status, status == 200 if is_true else 400)
            expected_status = 200 if is_true else 400
            print(expected_status)
            assert status == expected_status
            print(is_true)
            assert (body.get('error') is None) == is_true
            assert (body.get('access_token') is None) != is_true
            assert (body.get('refresh_token') is None) != is_true
            assert (body.get('expires_in') is None) != is_true
            assert (body.get('token_type') is None) != is_true
            assert (body.get('scope') is None) != is_true
            if is_true:
                assert body.get('scope') == ' '.join(bearer_tokens_list[i][message_selector].scopes)
