from __future__ import annotations
from typing import List

import pytest
import firefly as ff
import json
import firefly_iaaa.domain as domain

async def test_create_token_code(client, system_bus, registry, bearer_messages: List[ff.Message],user_list):#, auth_service: OauthProvider, bearer_messages: List[ff.Message]):

    data = {
            'headers': bearer_messages[0]['active'].headers,
            'client_id': bearer_messages[0]['active'].client_id,
            'grant_type': bearer_messages[0]['active'].grant_type,
            'state': bearer_messages[0]['active'].state,
            'username': bearer_messages[0]['active'].username,
            'password': bearer_messages[0]['active'].password,
            'code': bearer_messages[0]['active'].code,
            'code_verifier': bearer_messages[0]['active'].code_verifier,
    }
    initial_response = await client.post('/firefly-iaaa/iaaa/create_token', data=json.dumps(data), headers={'Origin': 'abc'})
    assert initial_response.status == 200
    resp = json.loads(await initial_response.text())
    assert resp['access_token'] is not None
    assert resp['refresh_token'] is not None
    assert resp['expires_in'] == 3600
