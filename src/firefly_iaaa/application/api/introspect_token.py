from __future__ import annotations

import firefly as ff
import json
from firefly_iaaa.application.api.generic_oauth_endpoint import GenericOauthEndpoint


@ff.rest(
    '/iaaa/introspect', method='POST', tags=['public'], secured=True
)
class OauthTokenIntrospectionService(GenericOauthEndpoint):

    def __call__(self, **kwargs):
        kwargs = self._fix_email(kwargs)
        message = self._make_message(kwargs)

        headers, body, status =  self._oauth_provider.create_introspect_response(message)
        
        return self._make_response(json.loads(body), headers)

    def _make_message(self, incoming_kwargs: dict):
        headers = self._add_method_to_headers(incoming_kwargs)
        message_body = {
            'headers': headers,
            'client_id': self._get_client_id(incoming_kwargs.get('client_id')),
            'state': incoming_kwargs.get('state'),
            'token': incoming_kwargs.get('token')
        }

        if incoming_kwargs.get('username'):
            message_body['username'] = incoming_kwargs.get('username') 
        if incoming_kwargs.get('password'):
            message_body['password'] = incoming_kwargs.get('password') 
        if incoming_kwargs.get('client_secret'):
            message_body['client_secret'] = incoming_kwargs.get('client_secret') 
        if not message_body['token']:
            if incoming_kwargs.get('access_token'):
                message_body['token'] = incoming_kwargs.get('access_token') 
        if not message_body['token']:
            if incoming_kwargs.get('refresh_token'):
                message_body['token'] = incoming_kwargs.get('refresh_token')
        if incoming_kwargs.get('token_type_hint'):
            message_body['token_type_hint'] = incoming_kwargs.get('token_type_hint')

        return self._message_factory.query(
            name='OauthIntrospectTokenMessage',
            data=message_body
        )
