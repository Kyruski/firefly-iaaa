from __future__ import annotations
from typing import List

import pytest
import firefly as ff
import json
import firefly_iaaa.domain as domain

async def test_auth_request(client, system_bus, registry, bearer_messages: List[ff.Message]):#, auth_service: OauthProvider, bearer_messages: List[ff.Message]):
    data = {
            'headers': bearer_messages[0]['active'].headers,
            'client_id': bearer_messages[0]['active'].client_id,
            'username': bearer_messages[0]['active'].username,
            'password': bearer_messages[0]['active'].password,
            'response_type': bearer_messages[0]['active'].response_type,
            'code_challenge': bearer_messages[0]['active'].code_challenge,
            'code_challenge_method': bearer_messages[0]['active'].code_challenge_method,
            'state': bearer_messages[0]['active'].state,
    }

    initial_response = await client.post('/firefly-iaaa/iaaa/authorization_request', data=json.dumps(data), headers={'Origin': 'abc'})

    resp = json.loads(await initial_response.text())
    assert isinstance(resp['scopes'], list)
    assert resp['credentials_key'] is not None
    assert resp['client_id'] is not None

    data = {
        'headers': data['headers'],
        'client_id': resp['client_id'],
        'scopes': resp['scopes'],
        'credentials_key': resp['credentials_key'],
    }

    creation_response = await client.post('/firefly-iaaa/iaaa/create_authorization', data = json.dumps(data), headers={'Origin': 'abc'})

    assert creation_response.status < 400
