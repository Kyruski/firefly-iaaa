#  Copyright (c) 2019 JD Williams
#
#  This file is part of Firefly, a Python SOA framework built by JD Williams. Firefly is free software; you can
#  redistribute it and/or modify it under the terms of the GNU General Public License as published by the
#  Free Software Foundation; either version 3 of the License, or (at your option) any later version.
#
#  Firefly is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
#  Public License for more details. You should have received a copy of the GNU Lesser General Public
#  License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  You should have received a copy of the GNU General Public License along with Firefly. If not, see
#  <http://www.gnu.org/licenses/>.

from __future__ import annotations

import firefly as ff
from oauthlib.oauth2 import RequestValidator, Server

import iam.domain as iam
from firefly_iaaa.domain.entity.grant import Grant
from firefly_iaaa.domain.service.request_validator import RequestValidator as IRequestValidator


class OauthlibRequestValidator(RequestValidator):
    _registry: ff.Registry = None

    def authenticate_client(self, request, *args, **kwargs):
        u = request.body['username']
        user = self._registry(iam.User).find_one_matching(
            (iam.User.c.email == u) | (iam.User.c.preferred_username == u)
        )
        return self.validate_user(
            request.body['username'], request.body['password'], user.client, request, *args, **kwargs
        )

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        client = self._get_client(client_id)
        if client:
            request.client = client
            return True
        return False

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        client = client or self._get_client(client_id)
        grant = self._registry(Grant).find_one_matching(
            (Grant.c.client_id == client.client_id) & (Grant.c.code == code)
        )
        if not grant:
            return False
        return grant.validate_redirect_uri(redirect_uri)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        request.client = request.client or self._get_client(client_id)
        return request.client.default_redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        pass

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        pass

    def introspect_token(self, token, token_type_hint, request, *args, **kwargs):
        pass

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        pass

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        pass

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        pass

    def save_bearer_token(self, token, request, *args, **kwargs):
        pass

    def validate_bearer_token(self, token, scopes, request):
        pass

    def validate_client_id(self, client_id, request, *args, **kwargs):
        client = self._get_client(client_id)
        if client:
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        pass

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        pass

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        request.client = request.client or self._get_client(client_id)
        return request.client.validate_redirect_uri(redirect_uri)

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        pass

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return client.validate_response_type(response_type)

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return client.validate_scopes(scopes)

    def validate_user(self, username, password, client, request, *args, **kwargs):
        if client.user.correct_password(password):
            request.user = client.user.email
            return True
        return False

    def get_code_challenge_method(self, code, request):
        pass

    def _get_client(self, client_id: str):
        return self._registry(iam.Client).find(client_id)


class IamRequestValidator(IRequestValidator):
    def __init__(self, validator: OauthlibRequestValidator):
        self._server = Server(validator)

    def validate_pre_auth_request(self, request: ff.Message):
        http_request = request.headers.get('http_request')
        return self._server.validate_authorization_request(
            f'{http_request["headers"]["Host"]}{http_request["url"]}',
            http_request['method'],
            '',
            http_request['headers']
        )

    def validate_post_auth_request(self, request: ff.Message):
        pass

    def create_response(self, request: ff.Message):
        return self._server.create_authorization_response(
            request.headers.get('uri'), request.headers.get('http_method'), request.to_dict(), request.headers
        )
