from __future__ import annotations

import firefly as ff
import firefly_iaaa.domain as domain
from firefly_iaaa.application.service.generic_oauth_endpoint import GenericOauthEndpoint


@ff.rest('/iaaa/authorization-request', method='POST', tags=['public'])
class OauthAuthorizationRequestService(GenericOauthEndpoint):
    _cache: ff.Cache = None
    _registry: ff.Registry = None

    def __call__(self, **kwargs):
        message = self._make_message(kwargs) #! check more

        scopes, credentials, credentials_key = self._oauth_provider.validate_pre_auth_request(message)
        # if status == 200:
        #     body = json.loads(body)
        # #? Add headers?
        resp = {
            'redirect_uri': credentials.get('redirect_uri'),
            'client_id': credentials.get('client_id'),
            'scopes': scopes,
            'credentials_key': credentials_key,
            'response_type': credentials.get('response_type'),

        }
        if 'code_challenge' in credentials:
            resp['code_challenge'] = credentials['code_challenge']
        if 'code_challenge_method' in credentials:
            resp['code_challenge_method'] = credentials['code_challenge_method']
        # if 'claims' in credentials:
        #     kwargs['claims'] = json.dumps(credentials['claims'])
        return resp

    def _make_message(self, incoming_kwargs: dict):
        headers = self._add_method_to_headers(incoming_kwargs)
        message_body = {
            'headers': headers,
            #add state
            'client_id': self._get_client_id(incoming_kwargs.get('client_id')),
            'state': incoming_kwargs.get('state'),
            'response_type': incoming_kwargs.get('response_type'),
            'code_challenge': incoming_kwargs.get('code_challenge'),
        }

        if incoming_kwargs.get('username'):
            message_body['username'] = incoming_kwargs.get('username') 
        if incoming_kwargs.get('password'):
            message_body['password'] = incoming_kwargs.get('password') 
        if incoming_kwargs.get('client_secret'):
            message_body['client_secret'] = incoming_kwargs.get('client_secret')


        message = self._message_factory.query(
            name='OauthAuthorizationRequestMessage',
            data=message_body
        )
        return message

@ff.rest(
    '/iaaa/create-authorization', method='POST', tags=['public']
)
class OauthCreateAuthorizationService(GenericOauthEndpoint):
    _cache: ff.Cache = None

    def __call__(self, **kwargs):
        message = self._make_message(kwargs) #! check more
        headers, body, status = self._oauth_provider.validate_post_auth_request(message)

        if not headers and not body and not status:
            raise ff.UnauthorizedError()

        return ff.Envelope.wrap({}).add_forwarding_address(headers['Location'])


    def _make_message(self, incoming_kwargs: dict):
        headers = self._add_method_to_headers(incoming_kwargs)
        message_body = {
            'headers': headers,
            'state': incoming_kwargs.get('state'),
            'redirect_uri': incoming_kwargs.get('redirect_uri'),
            'client_id': incoming_kwargs.get('client_id'),
            'scopes': incoming_kwargs.get('scopes'),
            'credentials_key': incoming_kwargs.get('credentials_key'),
            'response_type': incoming_kwargs.get('response_type')
        }


        return self._message_factory.query(
            name='OauthCreateAuthorizationMessage',
            data=message_body
        )
