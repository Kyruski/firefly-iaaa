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
    _add_haders_from_kernel: domain.AddHeadersFromKernel = None

    def __call__(self, **kwargs):
        pass

    def _add_method_to_headers(self, incoming_kwargs: dict, http_method: str = 'POST'):
        print('HEADERS Before SETTING METHOD', http_method, incoming_kwargs)
        incoming_kwargs = self._add_headers_from_kernel(incoming_kwargs)
        if incoming_kwargs.get('headers'):
            try:
                headers = incoming_kwargs['headers']['http_request'].get('headers')
            except KeyError:
                headers = incoming_kwargs['headers']
            headers['method'] = incoming_kwargs['headers']['http_request'].get('method')
        else:
            headers = {'method': http_method}
        print('HEADERS AFTER SETTING METHOD', headers)
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
