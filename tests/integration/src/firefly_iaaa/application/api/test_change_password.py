from __future__ import annotations
from typing import List
import uuid

import firefly as ff
import json

from firefly_iaaa.domain.entity.tenant import Tenant
from firefly_iaaa.domain.entity.user import User

async def test_change_password(client, registry, cache):
    username = 'user123@yahoo.com'
    old_password = '123abc'
    new_password = '789xyz'

    tenant = Tenant(name=f'user_{username}')
    registry(Tenant).append(tenant)
    new_user = User.create(email=username, password=old_password, tenant=tenant)

    # Check missing fields and user not existing
    request_id = str(uuid.uuid4())
    cache.set(request_id, {'message': 'reset', 'username': username}, ttl=1800)

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'old_password': old_password}))
    assert first_response.status == 200
    first_response = json.loads(await first_response.text())
    assert first_response['message'] == 'error'

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'request_id': request_id}))
    assert first_response.status == 200
    first_response = json.loads(await first_response.text())
    assert first_response['message'] == 'error'

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'request_id': request_id, 'new_password': new_password}))
    assert first_response.status == 200
    first_response = json.loads(await first_response.text())
    assert first_response['message'] == 'error'

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'request_id': request_id, 'old_password': old_password}))
    assert first_response.status == 200
    first_response = json.loads(await first_response.text())
    assert first_response['message'] == 'error'

    registry(User).append(new_user)
    registry(User).commit()
    user = registry(User).find(lambda x: x.email.lower() == username)
    assert user.correct_password(old_password)
    assert not user.correct_password(new_password)

    #Check when user exists
    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'request_id': request_id, 'new_password': old_password}))
    assert first_response.status == 200
    user = registry(User).find(lambda x: x.email.lower() == username)
    assert user.correct_password(old_password)
    assert not user.correct_password(new_password)

    #Check request id invalid
    second_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'request_id': request_id, 'new_password': new_password}))
    assert second_response.status == 200
    second_response = json.loads(await second_response.text())
    assert second_response['message'] == 'error'
    user = registry(User).find(lambda x: x.email.lower() == username)
    assert user.correct_password(old_password)
    assert not user.correct_password(new_password)

    request_id = str(uuid.uuid4())
    cache.set(request_id, {'message': 'reset', 'username': username}, ttl=1800)

    third_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'request_id': request_id, 'new_password': new_password}))
    assert third_response.status == 200
    user = registry(User).find(lambda x: x.email.lower() == username)
    assert not user.correct_password(old_password)
    assert user.correct_password(new_password)

    fourth_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'request_id': request_id, 'new_password': new_password}))
    assert fourth_response.status == 200
    fourth_response = json.loads(await fourth_response.text())
    assert fourth_response['message'] == 'error'
    user = registry(User).find(lambda x: x.email.lower() == username)
    assert not user.correct_password(old_password)
    assert user.correct_password(new_password)

    request_id = str(uuid.uuid4())
    cache.set(request_id, {'message': 'reset', 'username': username}, ttl=1800)

    fifth_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'request_id': request_id, 'new_password': old_password}))
    assert fifth_response.status == 200
    user = registry(User).find(lambda x: x.email.lower() == username)
    assert user.correct_password(old_password)
    assert not user.correct_password(new_password)
