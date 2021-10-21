from __future__ import annotations
from typing import List
import os

import pytest
import firefly as ff
import json
import firefly_iaaa.domain as domain
import firefly_iaaa.application as application

async def test_authorize_request(transport, bearer_messages: List[ff.Message], message_factory, sut, kernel, user_list, auth_service, registry):
    transport.register_handler('iaaa.GetClientUserAndToken', lambda t: {
            'decoded': auth_service.decode_token(bearer_messages[0]['active'].access_token, bearer_messages[0]['active'].client_id),
            'user': user_list[-2],
            'client_id': bearer_messages[0]['active'].client_id,
        })
    kernel.user.id = bearer_messages[0]['active'].client_id
    data = {
            'headers': bearer_messages[0]['active'].headers,
            'state': bearer_messages[0]['active'].state,
            'username': bearer_messages[0]['active'].username,
            'password': bearer_messages[0]['active'].password,
    }

    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )
    validated = sut.handle(message)
    assert not validated

    data['access_token'] = bearer_messages[0]['active'].access_token
    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )
    validated = sut.handle(message)
    assert validated

@pytest.fixture()
def sut(container):
    cont = container.build(application.AuthorizeRequest)
    return cont
