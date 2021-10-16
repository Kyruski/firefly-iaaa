from __future__ import annotations
from abc import ABC

import firefly as ff
import firefly_iaaa.domain as domain


class GenericOauthEndpoint(ff.ApplicationService, ABC):
    _oauth_provider: domain.OauthProvider = None
    _kernel: ff.Kernel = None
    _message_factory: ff.MessageFactory = None

    def __call__(self, **kwargs):
        pass

    def _get_client_id(self, client_id):
        return client_id or self._kernel.user.id

    def _add_method_to_headers(self, incoming_kwargs: dict):
        try:
            headers = incoming_kwargs['headers']['http_request'].get('headers')
        except KeyError:
            headers = incoming_kwargs['headers']
        headers['method'] = incoming_kwargs['headers']['http_request'].get('method')

        return headers

    def _make_message(self, incoming_kwargs: dict):
        pass
