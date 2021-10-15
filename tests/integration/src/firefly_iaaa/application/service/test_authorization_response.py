from __future__ import annotations
from typing import List

import pytest
import firefly as ff
import json
import firefly_iaaa.domain as domain

async def test_auth_request(client, registry, bearer_messages_list: List[ff.Message]):#, auth_service: OauthProvider, bearer_messages_list: List[ff.Message]):
    data = {
            'headers': bearer_messages_list[0]['active'].headers,
            'token': bearer_messages_list[0]['active'].token,
            "client_id": bearer_messages_list[0]['active'].client_id,
            "state": bearer_messages_list[0]['active'].state,
            "username": bearer_messages_list[0]['active'].username,
            "password": bearer_messages_list[0]['active'].password,
    }
    y = registry(domain.Client).find(bearer_messages_list[0]['active'].client_id)
    print('client found is: ', y)
    # assert False
    x = await client.post('/firefly-iaaa/iaaa/authorization_request', data=json.dumps(data))
    print(x)
    data = json.loads(await x.text())
    print(data)
    assert False