from __future__ import annotations
from typing import List

import pytest
import firefly as ff
import json
import firefly_iaaa.domain as domain

async def test_create_token_code_from_auth(client, system_bus, registry, bearer_messages: List[ff.Message],user_list):#, auth_service: OauthProvider, bearer_messages: List[ff.Message]):

    data = {
            'headers': bearer_messages[0]['active'].headers,
            'state': bearer_messages[0]['active'].state,
            'username': bearer_messages[0]['active'].username,
    }
    
    first_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await first_response.text())
    assert 'error' in resp

    data['grant_type'] = bearer_messages[0]['active'].grant_type
    second_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await second_response.text())
    assert 'error' in resp

    data['client_id'] = bearer_messages[0]['active'].client_id
    third_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await third_response.text())
    assert 'error' in resp

    data['password'] = bearer_messages[0]['active'].password
    fourth_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await fourth_response.text())
    assert 'error' in resp

    data['code'] = bearer_messages[0]['active'].code
    fifth_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await fifth_response.text())
    assert 'error' in resp

    data['code_verifier'] = bearer_messages[0]['active'].code_verifier
    final_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    assert final_response.status == 200
    resp = json.loads(await final_response.text())
    assert resp['access_token'] is not None
    assert resp['refresh_token'] is not None
    assert resp['expires_in'] == 3600

    final_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await final_response.text())
    assert 'error' in resp

async def test_create_token_code_from_refresh(client, system_bus, registry, bearer_messages: List[ff.Message],user_list):#, auth_service: OauthProvider, bearer_messages: List[ff.Message]):

    data = {
            'headers': bearer_messages[1]['active'].headers,
            'state': bearer_messages[1]['active'].state,
            'username': bearer_messages[1]['active'].username,
    }
    
    first_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await first_response.text())
    assert 'error' in resp

    data['grant_type'] = bearer_messages[1]['active'].grant_type
    second_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await second_response.text())
    assert 'error' in resp

    data['client_id'] = bearer_messages[1]['active'].client_id
    third_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await third_response.text())
    assert 'error' in resp

    data['password'] = bearer_messages[1]['active'].password
    fourth_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await fourth_response.text())
    assert 'error' in resp

    data['refresh_token'] = bearer_messages[1]['active'].refresh_token
    final_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    assert final_response.status == 200
    resp = json.loads(await final_response.text())
    assert resp['access_token'] is not None
    assert resp['refresh_token'] is not None
    assert resp['expires_in'] == 3600

async def test_create_token_code_from_client_credentials(client, system_bus, registry, bearer_messages: List[ff.Message],user_list):#, auth_service: OauthProvider, bearer_messages: List[ff.Message]):

    data = {
            'headers': bearer_messages[3]['active'].headers,
            'state': bearer_messages[3]['active'].state,
    }
    
    first_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await first_response.text())
    assert 'error' in resp

    data['grant_type'] = bearer_messages[3]['active'].grant_type
    second_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await second_response.text())
    assert 'error' in resp

    data['client_id'] = bearer_messages[3]['active'].client_id
    third_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    resp = json.loads(await third_response.text())
    assert 'error' in resp

    data['client_secret'] = bearer_messages[3]['active'].client_secret
    final_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    assert final_response.status == 200
    resp = json.loads(await final_response.text())
    assert resp['access_token'] is not None
    assert 'refresh_token' not in resp
    assert resp['expires_in'] == 3600