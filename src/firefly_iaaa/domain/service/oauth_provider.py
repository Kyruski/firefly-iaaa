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
from datetime import datetime, timedelta
import os
from typing import KeysView
import uuid

import firefly as ff
from firefly_iaaa import domain
import jwt
from oauthlib.oauth2 import Server
from oauthlib.common import Request

from .request_validator import OauthRequestValidators


class OauthProvider(ff.DomainService):
    _cache: ff.Cache = None
    _secret_key: str = None
    _issuer: str = None
    _registry: ff.Registry = None

    def __init__(self, validator: OauthRequestValidators):
        # with open(os.environ['PEM'], 'rb') as privatefile:
        #     pem_key = privatefile.read()

        # self.secret = pem_key
        # self.issuer = os.environ['ISSUER']
        self._server = Server(
            validator, #need to make sure this is instantiated
            token_generator=(lambda x: self.generate_token(x, 'access_token')),
            refresh_token_generator=(lambda x: self.generate_token(x, 'refresh_token')),
            token_expires_in=3600
        )

    def generate_token(self, request, token_type):
        token = {
            'jti': str(uuid.uuid4()),
            'aud': request.client_id,
            'iss': self._issuer,
            'scope': ' '.join(request.scopes)
        }
        if token_type == 'access_token':
            token['exp'] = datetime.utcnow() + timedelta(seconds=request.expires_in)
        token = jwt.encode(token, self._secret_key, algorithm='HS256')
        return token

    def validate_pre_auth_request(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        scopes, credentials = self._server.validate_authorization_request(uri, http_method, body, headers)

        credentials_key = str(uuid.uuid4())
        credentials = self._break_down_credentials(credentials)
        
        print('BEFORE SET CACHE', credentials)
        print('BEFORE SET CACHE', credentials_key)
        self._cache.set(credentials_key, value=credentials, ttl=180)
        return scopes, credentials, credentials_key

    def validate_post_auth_request(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        credentials_key = body.get('credentials_key')
        if not credentials_key:
            return None, None, None

        credentials = self._cache.get(credentials_key)
        if not credentials:
            return None, None, None

        credentials = self._build_up_credentials(credentials)
        
        if not request.scopes:
            return None, None, None
        headers, body, status = self._server.create_authorization_response(uri, http_method, body, headers, scopes=request.scopes, credentials=credentials)

        if headers.get('Location'):
            self._cache.delete(credentials_key)
        return headers, body, status

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


    def authenticate_client(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        oauth_request = Request(uri, http_method, body, headers)
        return self._server.request_validator.authenticate_client(oauth_request) #!! Check

    def decode_token(self, token, audience):
        if token.lower().startswith('bearer'):
            token = token.split(' ')[-1]
        try:
            return jwt.decode(token, self._secret_key, 'HS256', audience=audience)
        except (jwt.DecodeError, ValueError) as e:
            return None

    @staticmethod
    def _get_request_params(request: ff.Message):
        uri = request.headers.get('Origin') or request.headers.get('origin') or request.headers.get('Referer') or request.headers.get('uri')
        if not uri:
            raise Exception('No Origin detected on request')
        http_method = request.headers.get('method') or request.headers.get('http_method')
        body = request.to_dict()
        headers = request.headers
        return uri, http_method, body, headers

    def _break_down_credentials(self, credentials):
        credentials['request'] = self.scrub_sensitive_data(credentials['request']).__dict__
        return credentials

    def _build_up_credentials(self, credentials):
        values = ('uri', 'http_method', 'body', 'headers')
        uri, http_method, body, headers, *_ = credentials['request'].values()
        request = Request(uri, http_method, body, headers)
        print(type(credentials['request']))
        print(credentials['request'])
        for k, v in credentials['request'].items():
            if k not in values:
                setattr(request, k, v)
        credentials['request'] = self._add_entities_to_credentials(request)

        return credentials

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
        try:
            request.tenant = request.tenant.id
        except AttributeError:
            try:
                request['tenant'] = request['tenant'].id
            except (KeyError, TypeError):
                pass
        return request

    def _add_entities_to_credentials(self, request: Request):
        try:
            client = self._registry(domain.Client).find(lambda x: x.client_id == request.client['client_id'])
            request.client = client
        except AttributeError:
            try:
                client = self._registry(domain.Client).find(lambda x: x.client_id == request['client']['client_id'])
                request['client'] = client
            except (KeyError, TypeError):
                pass
        try:
            user = self._registry(domain.User).find(lambda x: x.sub == request.user['sub'])
            request.user = user
        except (AttributeError, TypeError):
            try:
                user = self._registry(domain.User).find(lambda x: x.sub == request['user']['sub'])
                request['user'] = user
            except (KeyError, TypeError):
                pass
        try:
            tenant = self._registry(domain.Tenant).find(lambda x: x.id == request.tenant)
            request.tenant = tenant
        except (AttributeError, TypeError):
            try:
                tenant = self._registry(domain.Tenant).find(lambda x: x.id == request['tenant'])
                request['tenant'] = tenant
            except (KeyError, TypeError):
                pass
        return request