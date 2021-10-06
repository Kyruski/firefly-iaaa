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
import os
import uuid

import firefly as ff
from firefly.domain.service import cache
from oauthlib.oauth2 import Server
from oauthlib.common import Request

from firefly_iaaa.domain.service.request_validator import RequestValidator
from .request_validator import OauthlibRequestValidator
from oauthlib.oauth2.rfc6749 import tokens


class IamRequestValidator(RequestValidator): #does this need to inherit?
    _cache: ff.Cache = None

    def __init__(self, validator: OauthlibRequestValidator):
        with open('key.pem', 'rb') as privatefile:
            pem_key = privatefile.read()
        self._server = Server(
            validator, #need to make sure this is instantiated
            token_generator=tokens.signed_token_generator(
                pem_key,
                issuer="PwrLab"
            ),
            refresh_token_generator=tokens.signed_token_generator(
                pem_key,
                issuer="PwrLab"
            ),
        )

    def validate_pre_auth_request(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        scopes, credentials = self._server.validate_authorization_request(uri, http_method, body, headers)

        credentials_key = str(uuid.uuid4())
        self._cache.set(credentials_key, value=credentials, ttl=180) #don't know what info given
        credentials['request'] = self.scrub_sensitive_data(credentials['request'])
        return scopes, credentials, credentials_key


    def validate_post_auth_request(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        credentials_key = body.get('credentials_key')
        if not credentials_key:
            return None, None, None

        credentials = self._cache.get(credentials_key)
        if not credentials:
            return None, None, None
        scopes = credentials['request'].scopes
        headers, body, status = self._server.create_authorization_response(uri, http_method, body, headers, scopes=scopes, credentials=credentials)
        
        return headers, body, status

        pass

    def create_token_response(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        headers, body, status = self._server.create_token_response(uri, http_method, body, headers)
        return headers, body, status

    def create_response(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        return self._server.create_authorization_response(
            uri, http_method, body, headers
        )

    def verify_request(self, request: ff.Message, scopes):
        uri, http_method, body, headers = self._get_request_params(request)
        is_valid, req = self._server.verify_request(uri, http_method, body, headers, scopes=scopes)
        req = self.scrub_sensitive_data(req)
        return is_valid, req

    def create_introspect_response(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        headers, body, status = self._server.create_introspect_response(uri, http_method, body, headers)
        return headers, body, status

    def create_revocation_response(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        headers, body, status = self._server.create_revocation_response(uri, http_method, body, headers)
        return headers, body, status

    # def create_metadata_response(self, request: ff.Message):


    # def authenticate_client(self, request: ff.Message):
    #     uri, http_method, body, headers = self._get_request_params(request)
    #     oauth_request = Request(uri, http_method, body, headers)
    #     return self._server.request_validator.authenticate_client(oauth_request)

    @staticmethod
    def _get_request_params(request: ff.Message):
        uri = request.headers.get('uri')
        http_method = request.headers.get('http_method')
        body = request.to_dict()
        headers = request.headers
        return [uri, http_method, body, headers]

    @staticmethod
    def scrub_sensitive_data(request: Request):
        try:
            request.client = request.client.generate_scrubbed_client()
        except AttributeError:
            try:
                request['client'] = request['client'].generate_scrubbed_client()
            except (KeyError, TypeError):
                pass
        try:
            request.user = request.user.generate_scrubbed_user()
        except AttributeError:
            try:
                request['user'] = request['user'].generate_scrubbed_user()
            except (KeyError, TypeError):
                pass
        return request