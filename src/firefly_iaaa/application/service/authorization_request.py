from __future__ import annotations

import firefly as ff
import firefly_iaaa.domain as domain


# @ff.command_handler('firefly_iaaa.AuthorizationRequest')
@ff.rest('/iaaa/authorization_request', method='POST', tags=['public'])
class OauthAuthorizationRequestService(ff.ApplicationService):
    _oauth_provider: domain.OauthProvider = None
    _kernel: ff.Kernel = None
    _message_factory: ff.MessageFactory = ff.MessageFactory()
    _cache: ff.Cache = None

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
        # if 'nonce' in credentials:
        #     kwargs['nonce'] = credentials['nonce']
        # if 'claims' in credentials:
        #     kwargs['claims'] = json.dumps(credentials['claims'])

        #! return scopes, client
        return resp

    def _get_client_id(self, client_id):
        return client_id or self._kernel.user.id

    def _make_message(self, incoming_kwargs: dict):
        message_body = {
            'headers': incoming_kwargs['headers']['http_request'].get('headers'),
            'token': incoming_kwargs.get('token'),
            "client_id": self._get_client_id(incoming_kwargs.get('client_id')),
            "state": incoming_kwargs.get('state')
        }
        print('message body:', message_body['client_id'], 'kwargs', incoming_kwargs.get('client_id'))

        if incoming_kwargs.get('username'):
            message_body['username'] = incoming_kwargs.get('username') 
        if incoming_kwargs.get('password'):
            message_body['password'] = incoming_kwargs.get('password') 
        if incoming_kwargs.get('client_secret'):
            message_body['client_secret'] = incoming_kwargs.get('client_secret')


        message = self._message_factory.query(
            name='a1b2c3', #!??????
            data=message_body
        )
        return message

@ff.rest(
    '/iaaa/create_authorization', method='POST', tags=['public']
)
@ff.command_handler('firefly_iaaa.CreateAuthorization')
class OauthCreateAuthorizationService(ff.ApplicationService):
    _oauth_provider: domain.OauthProvider = None
    _kernel: ff.Kernel = None
    _message_factory: ff.MessageFactory = None
    _cache: ff.Cache = None

    def __call__(self, **kwargs):
        message = self._make_message(kwargs) #! check more
        
        headers, body, status = self._oauth_provider.validate_post_auth_request(message)


        #! return scopes, client
        return ff.Envelope.add_forwarding_address(headers['Location'])

    def _make_message(self, incoming_kwargs: dict):
        message_body = {
            'headers': incoming_kwargs.get('headers'),
            "state": incoming_kwargs.get('state'),
            'redirect_uri': incoming_kwargs.get('redirect_uri'),
            'client_id': incoming_kwargs.get('client_id'),
            'scopes': incoming_kwargs.get('scopes'),
            'credentials_key': incoming_kwargs.get('credentials_key'),
            'response_type': incoming_kwargs.get('response_type')
        }


        return self._message_factory.query(
            name='a1b2c3', #!??????
            data=message_body
        )
