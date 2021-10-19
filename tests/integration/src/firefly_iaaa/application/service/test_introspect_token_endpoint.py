from __future__ import annotations
from typing import List

import firefly as ff
import json
from .conftest import set_kernel_user

async def test_introspect_token_endpoint(client, kernel, registry, bearer_messages: List[ff.Message]):

    data = {
            'headers': bearer_messages[0]['active'].headers,
            'state': bearer_messages[0]['active'].state,
            'username': bearer_messages[0]['active'].username,
            'password': bearer_messages[0]['active'].password,
    }
    set_kernel_user(registry, kernel, bearer_messages[0]['active'])

    first_response = await client.post('/firefly-iaaa/iaaa/introspect_token', data=json.dumps(data), headers={'Referer': 'abc'})
    await assert_error(first_response)

    data['token'] = bearer_messages[0]['active'].refresh_token
    second_response = await client.post('/firefly-iaaa/iaaa/introspect_token', data=json.dumps(data), headers={'Referer': 'abc'})
    await assert_success(second_response, bearer_messages[0]['active'])


    data = {
            'headers': bearer_messages[3]['active'].headers,
            'state': bearer_messages[3]['active'].state,
            'username': bearer_messages[3]['active'].username,
    }
    set_kernel_user(registry, kernel, bearer_messages[3]['active'])

    third_response = await client.post('/firefly-iaaa/iaaa/introspect_token', data=json.dumps(data), headers={'Referer': 'abc'})
    await assert_error(third_response)

    data['token'] = bearer_messages[3]['active'].access_token
    data['client_secret'] = bearer_messages[3]['active'].client_secret

    fourth_response = await client.post('/firefly-iaaa/iaaa/introspect_token', data=json.dumps(data), headers={'Referer': 'abc'})
    await assert_success(fourth_response, bearer_messages[3]['active'])


async def assert_success(response, message):
    resp = json.loads(await response.text())
    assert response.status == 200
    assert resp['active']
    assert resp['scope'] == message.scopes
    
async def assert_error(response):
    resp = json.loads(await response.text())
    assert 'error' in resp
