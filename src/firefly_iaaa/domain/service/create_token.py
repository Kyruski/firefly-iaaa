from __future__ import annotations

import firefly as ff
import json

from firefly_iaaa import domain
from firefly_iaaa.application.api.generic_oauth_endpoint import GenericOauthEndpoint


class CreateToken(ff.DomainService):
    _oauth_provider: domain.OauthProvider = None
    _message_factory: ff.MessageFactory = None
    _get_client_id: domain.GetClientId = None
    _add_headers_from_kernel: domain.AddHeadersFromKernel = None
    _add_method_to_headers: domain.AddMethodToHeaders = None

    def __call__(self, passed_in_kwargs:dict, **kwargs):
        message = self._make_message(passed_in_kwargs)

        headers, body, status = self._oauth_provider.create_token_response(message)

        return [headers, json.loads(body)]

    def _make_message(self, incoming_kwargs: dict):
        print('INCOMING KWARGS TO CREATE TOKEN', incoming_kwargs)
        print('INCOMING KWARGS TO CREATE TOKEN', incoming_kwargs.get('client_id'))
        headers = self._add_method_to_headers(incoming_kwargs)
        message_body = {
            'headers': headers,
            'grant_type': incoming_kwargs.get('grant_type'),
            'client_id': self._get_client_id(incoming_kwargs.get('client_id')),
            'state': incoming_kwargs.get('state')
        }

        if incoming_kwargs.get('username'):
            message_body['username'] = incoming_kwargs.get('username') 
        if incoming_kwargs.get('password'):
            message_body['password'] = incoming_kwargs.get('password') 
        if incoming_kwargs.get('client_secret'):
            message_body['client_secret'] = incoming_kwargs.get('client_secret') 
        if incoming_kwargs.get('code'):
            message_body['code'] = incoming_kwargs.get('code') 
        if incoming_kwargs.get('code_verifier'):
            message_body['code_verifier'] = incoming_kwargs.get('code_verifier') 
        if incoming_kwargs.get('refresh_token'):
            message_body['refresh_token'] = incoming_kwargs.get('refresh_token')

        return self._message_factory.query(
            name='OauthCreateTokenMessage',
            data=message_body
        )
