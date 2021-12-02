from __future__ import annotations
from typing import List

import firefly as ff
import json

from firefly_iaaa.domain.entity.tenant import Tenant
from firefly_iaaa.domain.entity.user import User

async def test_change_password(client, kernel, registry):
    username = 'user123@yahoo.com'
    old_password = '123abc'
    new_password = '789xyz'

    tenant = Tenant(name=f'user_{username}')
    registry(Tenant).append(tenant)
    new_user = User.create(email=username, password=old_password, tenant=tenant)

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'username': username, 'old_password': old_password}))
    assert first_response.status == 500

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'old_password': old_password}))
    assert first_response.status == 500

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'username': username}))
    assert first_response.status == 500

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'username': username, 'new_password': new_password}))
    assert first_response.status == 500

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'username': username, 'old_password': old_password, 'new_password': new_password}))
    assert first_response.status == 500

    registry(User).append(new_user)
    registry(User).commit()
    user = registry(User).find(lambda x: x.email == username)
    assert user.correct_password(old_password)
    assert not user.correct_password(new_password)

    first_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'username': username, 'new_password': old_password, 'old_password': new_password}))
    assert first_response.status == 500
    user = registry(User).find(lambda x: x.email == username)
    assert user.correct_password(old_password)
    assert not user.correct_password(new_password)

    second_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'username': username, 'old_password': old_password, 'new_password': new_password}))
    assert second_response.status == 200
    user = registry(User).find(lambda x: x.email == username)
    assert not user.correct_password(old_password)
    assert user.correct_password(new_password)

    second_response = await client.post('/firefly-iaaa/iaaa/change-password', data=json.dumps({'username': username, 'new_password': old_password, 'old_password': new_password}))
    assert second_response.status == 200
    user = registry(User).find(lambda x: x.email == username)
    assert user.correct_password(old_password)
    assert not user.correct_password(new_password)
