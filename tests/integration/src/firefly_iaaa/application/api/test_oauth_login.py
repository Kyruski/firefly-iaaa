from __future__ import annotations
from typing import List

import firefly as ff
import json

async def test_oauth_login_endpoint(client, registry, bearer_messages: List[ff.Message], kernel):
    data = {
            'state': bearer_messages[2]['active'].state,
            'username': bearer_messages[2]['active'].username,
    }

    first_response = await client.post('/firefly-iaaa/iaaa/login', data=json.dumps(data), headers={'Referer': 'abc'})
    assert first_response.status == 500

    data['grant_type'] = bearer_messages[2]['active'].grant_type
    second_response = await client.post('/firefly-iaaa/iaaa/login', data=json.dumps(data), headers={'Referer': 'abc'})
    assert second_response.status == 500

    data['client_id'] = bearer_messages[2]['active'].email
    third_response = await client.post('/firefly-iaaa/iaaa/login', data=json.dumps(data), headers={'Referer': 'abc'})
    assert third_response.status == 500

    data['password'] = bearer_messages[2]['active'].password
    fourth_response = await client.post('/firefly-iaaa/iaaa/login', data=json.dumps(data), headers={'Referer': 'abc'})
    assert fourth_response.status == 200
    # assert fourth_response.cookies['accessToken'] is not None
    # assert fourth_response.cookies['refreshToken'] is not None
    # assert fourth_response.cookies['accessToken']['max-age'] in ('3600', 3600)
    resp = json.loads(await fourth_response.text())
    assert resp['message'] == 'success'

    
    data['password'] = 'wrong password'
    fifth_response = await client.post('/firefly-iaaa/iaaa/login', data=json.dumps(data), headers={'Referer': 'abc'})
    assert fifth_response.status == 403
