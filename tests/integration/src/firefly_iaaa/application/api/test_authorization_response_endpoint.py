from __future__ import annotations
from typing import List

import firefly as ff
import json
import pytest
import urllib
from aiohttp import ClientConnectionError
from .conftest import set_kernel_user

async def test_auth_request_endpoint(client, kernel, registry, bearer_messages: List[ff.Message]):
    data = {
            'client_id': bearer_messages[0]['active'].client_id,
            # 'username': bearer_messages[0]['active'].username,
            'state': bearer_messages[0]['active'].state,
    }
    set_kernel_user(registry, kernel, bearer_messages[0]['active'])

    first_response = await client.get('/firefly-iaaa/iaaa/authorize', params=data, headers={'Referer': 'abc'})
    assert first_response.status == 500

    data['response_type'] = bearer_messages[0]['active'].response_type
    second_response = await client.get('/firefly-iaaa/iaaa/authorize', params=data, headers={'Referer': 'abc'})
    assert second_response.status == 500

    # data['password'] = bearer_messages[0]['active'].password
    third_response = await client.get('/firefly-iaaa/iaaa/authorize', params=data, headers={'Referer': 'abc'})
    assert third_response.status == 500

    data['code_challenge'] = bearer_messages[0]['active'].code_challenge
    fourth_response = await client.get('/firefly-iaaa/iaaa/authorize', params=data, headers={'Referer': 'abc'})

    assert fourth_response._history is not None
    assert fourth_response._history[0].status == 303
    assert 'Location' in fourth_response._history[0]._headers
    assert 'scopes' in fourth_response._history[0]._headers['Location']
    assert 'credentials_key' in fourth_response._history[0]._headers['Location']
    assert 'client_id' in fourth_response._history[0]._headers['Location']
    assert fourth_response.status == 200

    params = urllib.parse.parse_qs(urllib.parse.urlparse(fourth_response._history[0]._headers['Location']).query)
    assert 'client_id' in params
    client_id = params['client_id'][0]
    assert 'scopes' in params
    scopes = params['scopes'][0].strip('][').split(', ')
    assert 'credentials_key' in params
    credentials_key = params['credentials_key'][0]
    assert 'redirect_uri' in params
    redirect_uri = params['redirect_uri'][0]


    print('aaaaaaaaaaaaaaaaaaaa', redirect_uri)
    # missing credentials key
    data = {
        'client_id': client_id,
        'scopes': [scopes[0]],
        'redirect_uri': redirect_uri,
    }
    token = bearer_messages[0]['active'].access_token
    kernel.http_request = kernel.http_request or { 'headers': {}}

    kernel.http_request['headers'].update({'Authorization': f'Bearer {token}'})
    creation_response_1 = await client.post('/firefly-iaaa/iaaa/authorize', data = json.dumps(data), headers={'Referer': 'abc'})
    assert creation_response_1.status == 401

    data['credentials_key'] = credentials_key
    with pytest.raises(ClientConnectionError) as e:
        creation_response_2 = await client.post('/firefly-iaaa/iaaa/authorize', data = json.dumps(data), headers={'Referer': 'abc'})
    assert False
