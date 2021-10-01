from __future__ import annotations
from typing import List
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User
import firefly as ff

from firefly_iaaa.infrastructure.service.request_validator import IamRequestValidator

def test_verify_request(bearer_messages_list: List[ff.Message], auth_service: IamRequestValidator, bearer_tokens_list: List[BearerToken], user_list: List[User], client_list: List[Client]):

    for i in range(6):
        for x in range(3):
            for y in range(2):
                message_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
                message = bearer_messages_list[i][message_selector]['GET']
                scopes = bearer_tokens_list[i][message_selector].scopes if y == 0 else ['aaa', 'bbb']
                validated, resp = auth_service.verify_request(message, scopes)

                is_true = ((x == 0) and y == 0)
                assert validated == is_true

                if is_true:
                    assert resp.user == user_list[-2] if is_true else None
                    assert resp.client == client_list[i] if is_true else None
                    assert resp.scopes == scopes
                else:
                    assert resp.user is None
                    assert resp.client is None
                    assert resp.scopes == scopes
