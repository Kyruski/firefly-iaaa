from __future__ import annotations

import json

async def test_reset_password(client, transport, cache):
    transport.register_handler('firefly_messaging.PasswordReset', lambda x: x)

    username = 'user123@yahoo.com'

    first_response = await client.post('/firefly-iaaa/iaaa/reset-password', data=json.dumps({}))
    assert first_response.status == 500
    assert not cache.list()

    first_response = await client.post('/firefly-iaaa/iaaa/reset-password', data=json.dumps({'username': username}))
    assert first_response.status == 200
    cache_list = cache.list()
    assert len(cache_list) == 1
    assert list(cache_list)[0][1]['value']['username'] == username
    assert list(cache_list)[0][1]['value']['message'] == 'reset'
