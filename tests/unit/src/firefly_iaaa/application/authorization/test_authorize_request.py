from __future__ import annotations
from typing import List
import os

import pytest
import firefly as ff
import firefly_iaaa.application as application
import firefly_iaaa.domain as domain

async def test_authorize_request(bearer_messages_list: List[ff.Message], message_factory, sut, kernel, registry, system_bus):

    kernel.user.id = bearer_messages_list[0]['active'].client_id

    data = {
            'headers': bearer_messages_list[0]['active'].headers,
    }

    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )

    validated = sut.handle(message)
    assert not validated

    data['scopes'] = 'abc 123'
    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )

    validated = sut.handle(message)
    assert not validated

    data['scopes'] = bearer_messages_list[0]['active'].scopes
    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )

    validated = sut.handle(message)
    assert not validated

    data['access_token'] = bearer_messages_list[0]['active'].access_token
    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )
    validated = sut.handle(message)
    assert validated

@pytest.fixture()
def sut(container):
    cont = container.build(application.OauthAuthorizeRequest)
    return cont
