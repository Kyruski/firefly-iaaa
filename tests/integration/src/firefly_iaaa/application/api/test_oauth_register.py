from __future__ import annotations
import os

import json
import pytest
from firefly_iaaa import domain

async def test_oauth_register_endpoint(client, registry, consumer_client):
    data = {
            'state': 'a1b2c3',
            'username': 'abc@email.com',
    }

    os.environ['CONSUMER_CLIENT_ID'] = consumer_client.client_id

    first_response = await client.post('/firefly-iaaa/iaaa/register', data=json.dumps(data), headers={'Referer': 'abc'})
    assert first_response.status == 200
    assert first_response
    user = registry(domain.User).find(lambda x: x.email == data['username'])
    assert not user
    resp = json.loads(await first_response.text())
    assert 'error' in resp

    data['password'] = 'pAssw0rd!'
    second_response = await client.post('/firefly-iaaa/iaaa/register', data=json.dumps(data), headers={'Referer': 'abc'})
    assert second_response.status == 200

    resp = json.loads(await second_response.text())
    assert resp['message'] == 'success'
    assert resp['data']['access_token'] is not None
    assert resp['data']['refresh_token'] is not None

    user = registry(domain.User).find(lambda x: x.email == data['username'])
    assert user

    third_response = await client.post('/firefly-iaaa/iaaa/register', data=json.dumps(data), headers={'Referer': 'abc'})
    assert third_response.status == 200
    resp = json.loads(await third_response.text())
    assert 'error' in resp

@pytest.fixture()
def consumer_client(registry, roles, scopes):
    tenant = domain.Tenant(name='ABC')
    role = domain.Role(name='Distributed Event Registrant', scopes=roles['consumer_role'][0].scopes)
    # self._registry(domain.Role).find(lambda x: x.name == 'Distributed Event Registrant')
    main_client = domain.Client.create(
            tenant=tenant,
            name='Consumer Client',
            allowed_response_types='token',
            default_redirect_uri=f'https://www.urix.com',
            redirect_uris=[f'https://www.uriy.com', 'https://www.fake.com'],
            grant_type='password',
            uses_pkce=False,
            scopes=scopes['faker_scope1'],
            roles=roles['consumer_role'],
        )
    registry(domain.Tenant).append(tenant)
    registry(domain.Client).append(main_client)
    registry(domain.Role).append(role)
    registry(domain.Tenant).commit()
    registry(domain.Client).commit()
    registry(domain.Role).commit()
    registry(domain.Scope).commit()
    return main_client