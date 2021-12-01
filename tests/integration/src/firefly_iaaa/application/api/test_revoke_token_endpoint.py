from __future__ import annotations
from typing import List

import pytest
import firefly as ff
import json
import firefly_iaaa.domain as domain

async def test_revoke_token_endpoint(client, system_bus, registry, bearer_messages: List[ff.Message],user_list):#, auth_service: OauthProvider, bearer_messages: List[ff.Message]):

    data = {
            'state': bearer_messages[0]['active'].state,
            'username': bearer_messages[0]['active'].username,
            'password': bearer_messages[0]['active'].password,
    }
    token = registry(domain.BearerToken).find(lambda x: x.refresh_token == bearer_messages[0]['active'].refresh_token)
    assert token.is_valid
    assert token.is_access_valid
    first_response = await client.post('/firefly-iaaa/iaaa/revoke', data=json.dumps(data), headers={'Referer': 'abc'})
    assert token.is_valid
    assert token.is_access_valid

    data['token'] = bearer_messages[0]['active'].refresh_token
    second_response = await client.post('/firefly-iaaa/iaaa/revoke', data=json.dumps(data), headers={'Referer': 'abc'})
    token = registry(domain.BearerToken).find(lambda x: x.refresh_token == bearer_messages[0]['active'].refresh_token)
    assert not token.is_valid
    assert not token.is_access_valid
    assert second_response.status == 200


    data = {
            'state': bearer_messages[1]['active'].state,
            'username': bearer_messages[1]['active'].username,
            'password': bearer_messages[1]['active'].password,
    }
    token = registry(domain.BearerToken).find(lambda x: x.access_token == bearer_messages[1]['active'].access_token)
    assert token.is_valid
    assert token.is_access_valid
    first_response = await client.post('/firefly-iaaa/iaaa/revoke', data=json.dumps(data), headers={'Referer': 'abc'})
    assert token.is_valid
    assert token.is_access_valid

    data['token'] = bearer_messages[1]['active'].access_token
    second_response = await client.post('/firefly-iaaa/iaaa/revoke', data=json.dumps(data), headers={'Referer': 'abc'})
    token = registry(domain.BearerToken).find(lambda x: x.access_token == bearer_messages[1]['active'].access_token)
    assert token.is_valid
    assert not token.is_access_valid
    assert second_response.status == 200