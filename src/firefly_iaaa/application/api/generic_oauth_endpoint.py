from __future__ import annotations

import firefly as ff
import firefly_iaaa.domain as domain
from firefly_iaaa.application.api.generic_endpoint import GenericEndpoint


class GenericOauthEndpoint(GenericEndpoint):
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

    def _fix_email(self, kwargs):
        if kwargs.get('username'):
            kwargs['username'] = kwargs['username'].lower()
        email = kwargs.get('email', kwargs.get('username'))
        if email:
            kwargs['email'] = email.lower()
        return kwargs