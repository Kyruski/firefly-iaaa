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
from typing import List

import firefly as ff
from oauthlib.oauth2 import RequestValidator, Server

# import iam.domain as iam
from firefly_iaaa import domain
# from firefly_iaaa.domain.entity.grant import Grant
from firefly_iaaa.domain.service.request_validator import RequestValidator as IRequestValidator


class OauthlibRequestValidator(RequestValidator):
    _registry: ff.Registry = None
    # _default_scopes: List[str] = ['abc', 'def', 'ghi']
    _valid_token_type_hints: List[str] = ['refresh_token', 'access_token']

    def authenticate_client(self, request, *args, **kwargs):
        #TODO: set client, but have to get first
        u = request.body['username']
        user = self._registry(domain.User).find_one_matching( #! changed from iam.User to domain.User
            (domain.User.email == u) | (domain.User.preferred_username == u) #! changed from iam.User.c to domain.User
        )
        request.client = #??? set client, but have to get first
        return self.validate_user(
            request.body['username'], request.body['password'], user.client, request, *args, **kwargs
        )

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        #* Done? #? Ensure non-confidential client??
        return self.validate_client_id(client_id, request)

    def client_authentication_required(self, request, *args, **kwargs):
        #TODO
        return super().client_authentication_required(request, *args, **kwargs) #??? What to add

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        #* Done?
        # client = client or self._get_client(client_id) #! Should already have client
        grant = self._registry(domain.Grant).find_one_matching(
            (domain.Grant.client_id == client.client_id) & (domain.Grant.code == code) #!!from Grant.c.code to Grant.code
        )
        if grant is None:
            return False
        return grant.validate_redirect_uri(redirect_uri)

    def get_code_challenge(self, code: domain.AuthorizationCode, request):
        #?????
        return code.challenge #? Might need to decode?
        # return super().get_code_challenge(code, request)

    def get_code_challenge_method(self, code: domain.AuthorizationCode, request): #? More checks needed?
        #?? done?
        # auth_code = self._get_authorization_code(code) #?? not needed?
        return code.challenge_method
        # pass 

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        #* Done
        # Should already have request.client from validate client beforehand
        # request.client = request.client or self._get_client(client_id)
        return request.client.default_redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        #* Done
        # Should already have request.client from validate client beforehand
        # client = self._get_client(client_id)
        return request.client.scopes
        pass

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        #* Done
        bearer_token, _ = self._get_bearer_token(refresh_token, 'refresh_token')
        return bearer_token.scopes

    def introspect_token(self, token, token_type_hint, request, *args, **kwargs):
        #! Needs more work
        bearer_token, _ = self._get_bearer_token(token, token_type_hint)
        resp = {
            'active': bearer_token.validate_access_token(),
            'scope': bearer_token.scope,
            'client_id': bearer_token.client.client_id,
            'username': bearer_token.user.username or bearer_token.user.email, #use whichever one isn't None
            'token_type': 'access_token' if token == bearer_token.access_token else 'refresh_token',
            'exp': bearer_token.expires_at.timestamp(),
            'iat': bearer_token.created_at.timestamp(),
            'nbf': bearer_token.activates_at.timestamp(),
            'sub': '', #????????? user?
            'aud': '', #????????? client?
            'iss': 'pwrlab', #!!!! double check
            'jti': 'JWT', #!! JWT string
        } if bearer_token else None
        request.token = resp

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        #* Done
        code.invalidate()

    def is_pkce_required(self, client_id, request):
        #* Done
        return request.code.requires_pkce()

    def is_within_original_scope(self, request_scopes, refresh_token, request, *args, **kwargs):
        #* Done
        bearer_token, _ = self._get_bearer_token(refresh_token, 'refresh_token')
        if bearer_token is None:
            return False
        return bearer_token.validate_scopes(request_scopes)

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        bearer_token, token_type = self._get_bearer_token(token, token_type_hint) #? Pass in token_type_hint as well?
        if bearer_token is not None:
            if token_type == 'refresh_token':
                bearer_token.invalidate()
            else:
                bearer_token.invalidate_access_token()

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        #!! COME BACK TO
        auth_code = domain.AuthorizationCode(
            client=request.client,
            user=request.user,
            scopes=request.scopes,
            code=code['code'],
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            redirect_uri=request.redirect_uri,
            challenge=request.code_challenge,
            challenge_method=request.code_challenge_method,
            claims=kwargs.get('claims') or None,
            )
        self._registry(domain.AuthorizationCode).append(auth_code)
        self._registry(domain.AuthorizationCode).commit()

    def save_bearer_token(self, token, request, *args, **kwargs):
        bearer_token = domain.BearerToken(
            client=request.client,
            user=request.user,
            scopes=request.scopes,
            access_token=token['access_token'],
            expires_at=datetime.utcnow() + timedelta(seconds=token.expires_at),
            refresh_token=token['refresh_token'],
            token_type=token['token_type'],
        ) #!!!! Not done
        self._registry(domain.BearerToken).append(bearer_token)
        self._registry(domain.BearerToken).commit()
        return request.client.redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        bearer_token, _ = self._get_bearer_token(token) #!?!?!!?! what is token_type_hint
        if bearer_token is None:
            return False
        return bearer_token.validate(scopes)

    def validate_client_id(self, client_id, request, *args, **kwargs):
        client = request.client or self._get_client(client_id)
        if client:
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        client = client or self._get_client(client_id)
        code = self._get_authorization_code(code)
        if code is not None and client is not None:
            request.user = code.user
            request.scopes = code.scopes
            request.claims = code.claims if code.claims is not None else None
            request.code.challenge = code.code.challenge if code.code.challenge is not None else None
            request.code.challenge_method = code.code.challenge_method if code.code.challenge_method is not None else None
            return code.validate(client)
        return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        return grant_type == client.grant_type

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return request.client.validate_redirect_uri(redirect_uri)

    def validate_refresh_token(self, refresh_token: str, client: domain.Client, request, *args, **kwargs):
        # client = request.client or client #self._get_client(refresh_token) #? Needed?
        bearer_token, _ = self._get_bearer_token(refresh_token, 'refresh_token')
        if bearer_token is None:
            return False

        return bearer_token.validate_refresh_token(refresh_token, client)

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return client.validate_response_type(response_type)

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return client.validate_scopes(scopes)

    def validate_user(self, username, password, client, request, *args, **kwargs):
        if client.user.correct_password(password):
            request.user = client.user.email
            return True
        return False

    def _get_client(self, client_id: str):
        return self._registry(domain.Client).find(client_id) #! changed from iam.Client to domain.Client

    def _get_bearer_token(self, token: str, token_type_hint: str = None):
        current_token_type = 0
        access_criteria = lambda x: (x.access_token == token)
        refresh_criteria = lambda x: (x.refresh_token == token)
        criteria = [access_criteria, refresh_criteria]
        if token_type_hint == self._valid_token_type_hints[1]:
            current_token_type = 1
        bearer_token = self._registry(domain.BearerToken).find(criteria[current_token_type]) #? Does a find need to be implemented? This could be refresh or access. Could pass in type of token
        token_type = self._valid_token_type_hints[current_token_type]
        if bearer_token is None:
            current_token_type = (current_token_type + 1) % 2
            bearer_token = self._registry(domain.BearerToken).find(criteria[current_token_type])
            token_type = self._valid_token_type_hints[current_token_type]
        return [bearer_token, token_type]

    def _get_authorization_code(self, code: str):
        return self._registry(domain.AuthorizationCode).find(code) if isinstance(code, str) else code

    def _generate_token(self):
        pass


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

    
