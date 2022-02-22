from __future__ import annotations

import firefly as ff
import json

from firefly_iaaa import domain
from firefly_iaaa.application.api.generic_oauth_endpoint import GenericOauthEndpoint


class CreateToken(ff.DomainService):
    _oauth_provider: domain.OauthProvider = None
    _message_factory: ff.MessageFactory = None
    _get_client_id: domain.GetClientId = None
    _add_method_to_headers: domain.AddMethodToHeaders = None

    def __call__(self, passed_in_kwargs:dict, **kwargs):
        message = self._make_message(passed_in_kwargs)

        headers, body, status = self._oauth_provider.create_token_response(message)

        return [headers, json.loads(body)]

    def _make_message(self, incoming_kwargs: dict):
        headers = self._add_method_to_headers(incoming_kwargs)
        message_body = {
            'headers': headers,
            'grant_type': incoming_kwargs.get('grant_type'),
            'client_id': self._get_client_id(incoming_kwargs.get('client_id')),
            'state': incoming_kwargs.get('state')
        }

        for field in ('username', 'password', 'client_secret', 'code', 'code_verifier', 'refresh_token', 'scopes', 'scope'):
            if incoming_kwargs.get(field):
                message_body[field] = incoming_kwargs.get(field)

        return self._message_factory.query(
            name='OauthCreateTokenMessage',
            data=message_body
        )
