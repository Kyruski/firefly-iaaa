from __future__ import annotations

import firefly as ff

from firefly_iaaa import application, domain


class AuthorizeRequest(ff.DomainService):
    _authorize_request: domain.OAuthAuthorizeRequest = None
    _message_factory: ff.MessageFactory = None
    _add_method_to_headers: domain.AddMethodToHeaders = None

    def __call__(self, **kwargs):
        if 'access_token' not in kwargs:
            return False
        return self._authorize_request(self._make_message(kwargs), **kwargs)

    def _make_message(self, incoming_kwargs: dict):
        headers = self._add_method_to_headers(incoming_kwargs)
        message_body = {
            'headers': headers,
            'access_token': incoming_kwargs.get('access_token'),
            
        }

        for field in ('username', 'password', 'scopes'):
            if incoming_kwargs.get(field):
                message_body[field] = incoming_kwargs.get(field)

        return self._message_factory.query(
            name='OauthAuthorizationRequestMessage',
            data=message_body
        )
