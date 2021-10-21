from __future__ import annotations
from typing import List

import firefly as ff
import json
from .conftest import set_kernel_user

async def test_auth_request_endpoint(client, kernel, registry, bearer_messages: List[ff.Message]):
    data = {
            'headers': bearer_messages[0]['active'].headers,
            'client_id': bearer_messages[0]['active'].client_id,
            'username': bearer_messages[0]['active'].username,
            'state': bearer_messages[0]['active'].state,
    }
    set_kernel_user(registry, kernel, bearer_messages[0]['active'])

    first_response = await client.post('/firefly-iaaa/iaaa/authorization-request', data=json.dumps(data), headers={'Referer': 'abc'})
    assert first_response.status == 500

    data['response_type'] = bearer_messages[0]['active'].response_type
    second_response = await client.post('/firefly-iaaa/iaaa/authorization-request', data=json.dumps(data), headers={'Referer': 'abc'})
    assert second_response.status == 500

    data['password'] = bearer_messages[0]['active'].password
    third_response = await client.post('/firefly-iaaa/iaaa/authorization-request', data=json.dumps(data), headers={'Referer': 'abc'})
    assert third_response.status == 500

    data['code_challenge'] = bearer_messages[0]['active'].code_challenge
    fourth_response = await client.post('/firefly-iaaa/iaaa/authorization-request', data=json.dumps(data), headers={'Referer': 'abc'})
    assert fourth_response.status == 200
    resp = json.loads(await fourth_response.text())

    assert isinstance(resp['scopes'], list)
    assert resp['credentials_key'] is not None
    assert resp['client_id'] is not None

    data = {
        'headers': data['headers'],
        'client_id': resp['client_id'],
        'scopes': resp['scopes'],
        'credentials_key': resp['credentials_key'],
    }
    data['scopes'] = [data['scopes'][0]]

    creation_response = await client.post('/firefly-iaaa/iaaa/create-authorization', data = json.dumps(data), headers={'Referer': 'abc'})

    assert creation_response.status < 400
