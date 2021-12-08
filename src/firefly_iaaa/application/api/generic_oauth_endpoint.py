from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Union

import firefly as ff
from firefly.domain.entity.messaging.envelope import Envelope
import firefly_iaaa.domain as domain


class GenericOauthEndpoint(ff.ApplicationService, ABC):
    _oauth_provider: domain.OauthProvider = None
    _kernel: ff.Kernel = None
    _registry: ff.Registry = None
    _message_factory: ff.MessageFactory = None

    @abstractmethod
    def __call__(self, **kwargs):
        pass

    def _get_client_id(self, client_id):
        if client_id:
            return client_id
        user = self._registry(domain.User).find(lambda x: x.sub == self._kernel.user.id)
        if not user:
            return self._kernel.user.id
        client = self._registry(domain.Client).find(lambda x: (x.tenant_id == user.tenant_id) | (x.client_id == user.sub))
        return client.client_id

    def _add_method_to_headers(self, incoming_kwargs: dict):
        try:
            headers = incoming_kwargs['headers']['http_request'].get('headers')
        except KeyError:
            headers = incoming_kwargs['headers']
        headers['method'] = incoming_kwargs['headers']['http_request'].get('method')

        return headers

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

        if headers:
            message = message.set_raw_request(headers)
        if forwarding_address:
            message = message.add_forwarding_address(forwarding_address)
        if cookies:
            message = message.set_cookies(cookies)
        return message