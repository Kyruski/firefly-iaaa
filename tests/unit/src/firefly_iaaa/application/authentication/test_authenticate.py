from __future__ import annotations
from typing import List

import pytest
import firefly as ff
import json
import firefly_iaaa.domain as domain
import firefly_iaaa.application as application

async def test_authenticate(bearer_messages_list: List[ff.Message], message_factory, sut, kernel, transport, auth_service, user_list):
    transport.register_handler('firefly_iaaa.GetClientUserAndToken', lambda t: {
        'decoded': auth_service.decode_token(bearer_messages_list[0]['active'].access_token, bearer_messages_list[0]['active'].client_id),
        'user': user_list[-2],
        'client_id': bearer_messages_list[0]['active'].client_id,
    })
    data = {
        'headers': bearer_messages_list[0]['active'].headers,
        'state': bearer_messages_list[0]['active'].state,
    }

    auth_token = bearer_messages_list[0]['active'].access_token
    http_request = {'headers': {'Host': '127.0.0.1:62244', 'Referer': 'abc', 'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate', 'User-Agent': 'Python/3.7 aiohttp/3.7.4.post0', 'Content-Length': '82', 'Content-Type': 'text/plain; charset=utf-8'}, 'method': 'POST', 'path': '/firefly-iaaa/iaaa/create-token', 'content_type': 'text/plain', 'content_length': 82, 'query': {}, 'url': '/firefly-iaaa/iaaa/create-token'}
    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )
    kernel.http_request = http_request
    kernel.user.id = bearer_messages_list[0]['active'].client_id
    validated = sut.handle(message)
    assert validated #kernel is unsecure first

    kernel.secured = True
    with pytest.raises(ff.UnauthenticatedError):
        validated = sut.handle(message)

    kernel.http_request['headers']['authorization'] = f'Bearer {auth_token}'
    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )
    validated = sut.handle(message)
    assert validated

    del kernel.http_request['headers']['authorization']
    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )
    with pytest.raises(ff.UnauthenticatedError):
        validated = sut.handle(message)

    
    data['access_token'] = bearer_messages_list[0]['active'].access_token
    message = message_factory.query(
        name='a1b2c3',
        data=data,
    )
    validated = sut.handle(message)
    assert validated

@pytest.fixture()
def sut(container, system_bus):
    cont = container.build(application.OAuthAuthenticator)
    cont.request = system_bus.request
    return cont