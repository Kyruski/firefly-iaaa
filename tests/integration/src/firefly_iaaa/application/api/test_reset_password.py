from __future__ import annotations

import json
from typing import List
from firefly_iaaa import domain
import boto3

async def test_reset_password(client, transport, cache, registry, context_map):
    # def abc(a):
    #     client = boto3.client('ses')
    #     print('aaaaaaaaaaaaaaaaaaaaa')
    #     print(a.__dict__['subject'], '\n', a.__dict__['text_body'], '\n', a.__dict__['html_body'], '\n', a.__dict__['from_address'], '\n', a.__dict__['to_address'], '\n', a.__dict__['cc_addresses'], '\n', a.__dict__['bcc_addresses'])
    #     response = client.send_email(
    #         Source=a.__dict__['from_address'],
    #         Destination={
    #             'ToAddresses': a.__dict__['to_address'],
    #             'CcAddresses': a.__dict__['cc_addresses'],
    #             'BccAddresses': a.__dict__['bcc_addresses'],
    #         },
    #         Message={
    #             'Subject': {
    #                 'Data': a.__dict__['subject'],
    #             },
    #             'Body': {
    #                 'Text': {
    #                     'Data': a.__dict__['text_body'],
    #                 },
    #                 'Html': {
    #                     'Data': a.__dict__['html_body'],
    #                 }
    #             }
    #         }
    #     )
    #     return response
    # transport.register_handler('firefly_messaging.SendSESEmail', abc)
    transport.register_handler('firefly_messaging.SendSESEmail', lambda x: {'MessageId': 'abc', 'ResponseMetadata': {'RequestId': 'a2591961-61ed-4f24-b200-7efa77804de9', 'HTTPStatusCode': 200}})

    username = 'jamey.boyett@pwrlab.com'

    first_response = await client.post('/firefly-iaaa/iaaa/reset-password', data=json.dumps({}))
    assert first_response.status == 500
    assert not cache.list()
    # print(context_map)
    second_response = await client.post('/firefly-iaaa/iaaa/reset-password', data=json.dumps({'username': username}))
    assert second_response.status == 200
    cache_list = cache.list()
    assert len(cache_list) == 0

    tenant = domain.Tenant(name='abc')
    user = domain.User.create(email=username, password='passwor13', tenant=tenant)
    registry(domain.Tenant).append(tenant)
    registry(domain.User).append(user)
    registry(domain.User).commit()
    registry(domain.Tenant).commit()

    third_response = await client.post('/firefly-iaaa/iaaa/reset-password', data=json.dumps({'username': username}))
    assert third_response.status == 200
    cache_list = cache.list()
    assert len(cache_list) == 1
    assert list(cache_list)[0][1]['value']['username'] == username
    assert list(cache_list)[0][1]['value']['message'] == 'reset'
    assert False