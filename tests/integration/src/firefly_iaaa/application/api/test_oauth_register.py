from __future__ import annotations
from typing import List

import firefly as ff
import json
from firefly_iaaa import domain

async def test_oauth_register_endpoint(client, registry, bearer_messages: List[ff.Message], kernel):
    data = {
            'state': bearer_messages[2]['active'].state,
            'username': 'abc@email.com',
    }

    first_response = await client.post('/firefly-iaaa/iaaa/register', data=json.dumps(data), headers={'Referer': 'abc'})
    assert first_response.status == 500
    user = registry(domain.User).find(lambda x: x.email == data['username'])
    assert not user

    data['password'] = bearer_messages[2]['active'].password
    second_response = await client.post('/firefly-iaaa/iaaa/register', data=json.dumps(data), headers={'Referer': 'abc'})
    assert second_response.status == 200
    print('aaaaaaaaaaaaaaaaaaaaaaa', second_response)
    print('bbbbbbbbbbbbbbbbbbbbb', second_response.cookies)
    assert second_response.cookies['accessToken'] is not None
    assert second_response.cookies['refreshToken'] is not None
    assert second_response.cookies['accessToken']['max-age'] in ('3600', 3600)
    resp = json.loads(await second_response.text())
    assert resp['message'] == 'success'

    user = registry(domain.User).find(lambda x: x.email == data['username'])
    assert user

    third_response = await client.post('/firefly-iaaa/iaaa/register', data=json.dumps(data), headers={'Referer': 'abc'})
    assert third_response.status == 200
    resp = json.loads(await third_response.text())
    assert 'error' in resp
