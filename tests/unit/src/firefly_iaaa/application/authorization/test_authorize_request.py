from __future__ import annotations
from typing import List
import os

import pytest
import firefly as ff
import firefly_iaaa.application as application
import firefly_iaaa.domain as domain

async def test_authorize_request(bearer_messages_list: List[ff.Message], message_factory, sut, kernel, registry):

    print(kernel.user.id)
    kernel.user.id = bearer_messages_list[0]['active'].client_id
    # set_kernel_user(registry, kernel, bearer_messages_list[0]['active'])
    print(kernel.user.id)
    data = {
            'headers': bearer_messages_list[0]['active'].headers,
            'state': bearer_messages_list[0]['active'].state,
            'username': bearer_messages_list[0]['active'].username,
            'password': bearer_messages_list[0]['active'].password,
    }

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
    cont = container.build(application.AuthorizeRequest)
    return cont
