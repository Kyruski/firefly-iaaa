from __future__ import annotations
from typing import List, Union

import firefly as ff
from firefly.domain.entity.messaging.envelope import Envelope
import firefly_iaaa.domain as domain


class GenericOauthEndpoint(ff.ApplicationService):
    _oauth_provider: domain.OauthProvider = None
    _kernel: ff.Kernel = None
    _registry: ff.Registry = None
    _message_factory: ff.MessageFactory = None
    _get_client_id: domain.GetClientId = None
    _add_method_to_headers: domain.AddMethodToHeaders = None

    def __call__(self, **kwargs):
        pass

    def _make_message(self, incoming_kwargs: dict):
        pass

    def _make_response(self, data: Union[dict, ff.Envelope] = None, headers: dict = None, forwarding_address: str = None, cookies: List[dict] = None):
        if isinstance(data, ff.Envelope):
            message = data
        else:
            message = {'message': 'success'}
            if data:
                message['data'] = data
            message = ff.Envelope.wrap(message)
        print('AFDGMDFSMGSDMF', message)
        print('AFDGMDFSMGSDMF', data)
        print('AFDGMDFSMGSDMF', headers)
        print('AFDGMDFSMGSDMF', forwarding_address)
        print('AFDGMDFSMGSDMF', cookies)
        if headers:
            print('headers', headers)
            message = message.set_raw_request(headers)
            print('WE GOT headers', message)
        if forwarding_address:
            print('forwarding_address', forwarding_address)
            message = message.add_forwarding_address(forwarding_address)
            print('WE GOT forwarding', message)
        if cookies:
            print('cookies', cookies)
            message = message.set_cookies(cookies)
            print('WE GOT cookies', message)
        print('WE GOT MESSAGE', message)
        return message

    def _fix_email(self, kwargs):
        if kwargs.get('username'):
            kwargs['username'] = kwargs['username'].lower()
        email = kwargs.get('email', kwargs.get('username'))
        if email:
            kwargs['email'] = email.lower()
        return kwargs