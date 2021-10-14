from __future__ import annotations

import firefly as ff
import firefly_iaaa.domain as domain
import firefly_iaaa.infrastructure as infra


@ff.rest(
    '/iaaa/revoke_token', method='POST', tags=['public']
)
@ff.command_handler('firefly_iaaa.TokenRevocation')
class OauthTokenRevocationService(ff.ApplicationService):
    _oauth_provider: infra.OauthProvider = None
    _kernel: ff.Kernel = None
    _message_factory: ff.MessageFactory = None

    def __call__(self, **kwargs):
        message = self._make_message(kwargs)

        headers, body, status =  self._oauth_provider.create_revocation_response(message)
        # if status == 200:
        #     body = json.loads(body)
        # #? Add headers?

        return body

    def _get_client_id(self, client_id):
        return client_id or self._kernel.user.id

    def _make_message(self, incoming_kwargs: dict):
        message_body = {
            'headers': incoming_kwargs.get('headers'),
            'token': incoming_kwargs.get('token'),
            "client_id": self._get_client_id(incoming_kwargs.get('client_id')),
            "state": incoming_kwargs.get('state')
        }

        if incoming_kwargs.get('username'):
            message_body['username'] = incoming_kwargs.get('username') 
        if incoming_kwargs.get('password'):
            message_body['password'] = incoming_kwargs.get('password') 
        if incoming_kwargs.get('client_secret'):
            message_body['client_secret'] = incoming_kwargs.get('client_secret')


        return self._message_factory.query(
            name='a1b2c3', #!??????
            data=message_body
        )
