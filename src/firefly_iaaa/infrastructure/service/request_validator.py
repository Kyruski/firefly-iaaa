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
from datetime import datetime, timedelta
from typing import List
import base64
from urllib.parse import unquote_plus

import firefly as ff
from oauthlib.oauth2 import RequestValidator, Server
from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import tokens

# import iam.domain as iam
from firefly_iaaa import domain
from firefly_iaaa.domain.entity import user
from firefly_iaaa.domain.entity.user import User


class OauthlibRequestValidator(RequestValidator):
    _registry: ff.Registry = None
    _valid_token_type_hints: List[str] = ['refresh_token', 'access_token']

    def authenticate_client(self, request, *args, **kwargs):
        if self._http_basic_authentication(request): #!this is not done!
            return True

        return self._http_headers_authentication(request)

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # client = request.client or self._get_client(client_id)
        # #? check if active?
        # if not client:
        #     return False
        #Authenticate (not validate)
        #*? Done? #? Ensure non-confidential client??
        if self.validate_client_id(client_id, request):
            return request.client.is_confidential()
        return False

    def client_authentication_required(self, request, *args, **kwargs):
        #Always authenticate when headers are present
        #!! Check if authentication string/header?
        if request.body.get('username') and request.body.get('password'):
            return True
        client = self._get_client(request.client_id)
        if not client:
            return False
        return client.is_confidential() #! Need more?
        # return super().client_authentication_required(request, *args, **kwargs) #??? What to add

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        #* Done?
        # client = client or request.client or self._get_client(client_id)
        auth_code = self._get_authorization_code(code)
        if not auth_code:
            return False
        return auth_code.client.client_id == client.client_id and auth_code.validate_redirect_uri(redirect_uri)

    def get_code_challenge(self, code, request):
        #?????
        auth_code = self._get_authorization_code(code) #?? not needed?
        #TODO: Might need to store encoded?
        #TODO: Is the code the auth code object or the stirng?

        if not auth_code:
            return None
        #??! Might need to encrypt
        return auth_code.challenge #? Might need to decode?

    def get_code_challenge_method(self, code, request): #? More checks needed?
        #?? done?
        auth_code = self._get_authorization_code(code) #?? not needed?
        #TODO: Is the code the auth code object or the stirng?

        if not auth_code:
            return None
        return auth_code.challenge_method

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        #* Done
        # Should already have request.client from validate client beforehand
        # client = request.client or self._get_client(client_id)

        # if not client:
        #     return None
        return request.client.default_redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        #* Done
        # Should already have request.client from validate client beforehand

        # client = request.client or self._get_client(client_id)

        # if not client:
        #     return None
        return request.client.scopes

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        #* Done
        bearer_token, _ = self._get_bearer_token(refresh_token, 'refresh_token')

        if not bearer_token:
            return None
        return bearer_token.scopes

    def introspect_token(self, token, token_type_hint, request, *args, **kwargs):
        #! Needs more work??
        #! Does this have claims on the request?
        bearer_token, token_type = self._get_bearer_token(token, token_type_hint)
        resp = self._generate_authorization_code(bearer_token, token_type)
        request.token = resp

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        #* Done
        auth_code = self._get_authorization_code(code) #?? not needed?

        #? check client_id (not needed?)

        if not auth_code:
            return
        auth_code.invalidate()

    def is_pkce_required(self, client_id, request):
        #*! Done
        #! Unsure if done
        #! NOT DONE
        # grant = self._registry(domain.Grant).find(
        #     (domain.Grant.client_id == client_id) & (domain.Grant.code == request.code)
        # )
        # client = request.client or self._get_client(client_id)
    
        # if not client:
        #     return False #??
        return request.client.requires_pkce()

    def is_within_original_scope(self, request_scopes, refresh_token, request, *args, **kwargs):
        #* Done
        bearer_token, _ = self._get_bearer_token(refresh_token, 'refresh_token')

        if not bearer_token:
            return False
        return bearer_token.validate_scopes(request_scopes)

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        bearer_token, token_type = self._get_bearer_token(token, token_type_hint) #? Pass in token_type_hint as well?

        if not bearer_token:
            return
        if token_type == 'refresh_token':
            bearer_token.invalidate()
        else:
            bearer_token.invalidate_access_token()

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        #!! COME BACK TO
        auth_code = self._generate_authorization_code(code, request, kwargs.get('claims'))
        self._registry(domain.AuthorizationCode).append(auth_code)
        # self._registry(domain.AuthorizationCode).commit() #??

    def save_bearer_token(self, token, request, *args, **kwargs):
        bearer_token = self._generate_bearer_token(token, request) #!!!! Not done
        self._registry(domain.BearerToken).append(bearer_token)
        # self._registry(domain.BearerToken).commit()
        return request.client.redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        bearer_token, _ = self._get_bearer_token(token)
        if not bearer_token:
            return False
        request.user = bearer_token.user
        request.client = bearer_token.client
        request.scopes = bearer_token.scopes
        return bearer_token.validate(scopes)

    def validate_client_id(self, client_id, request, *args, **kwargs):
        client = request.client or self._get_client(client_id)
        #? check if active?
        if not client:
            return False
        request.client = client
        return client.validate()

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # client = client or self._get_client(client_id)
        auth_code = self._get_authorization_code(code)

        if not auth_code: # or not client:
            return False
        request.user = auth_code.user
        request.scopes = auth_code.scopes
        if auth_code.claims:
            request.claims = auth_code.claims 
        if auth_code.challenge:
            request.code.challenge = auth_code.challenge
        if auth_code.challenge_method:
            request.code.challenge_method = auth_code.challenge_method
        return auth_code.validate(client)

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # client = client or request.client or self._get_client(client_id)

        # if not client:
        #     return False
        return client.validate_grant_type(grant_type)

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # client = request.client or self._get_client(client_id)

        # if not client:
        #     return False
        return request.client.validate_redirect_uri(redirect_uri)

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        # client = request.client or client #self._get_client(refresh_token) #? Needed?
        bearer_token, _ = self._get_bearer_token(refresh_token, 'refresh_token')

        if not bearer_token:
            return False
        return bearer_token.validate_refresh_token(refresh_token, client)

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        # client = client or request.client or self._get_client(client_id)

        # if not client:
        #     return False
        return client.validate_response_type(response_type)

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # client = client or request.client or self._get_client(client_id)

        # if not client:
        #     return False
        return client.validate_scopes(scopes)

    def validate_user(self, username, password, client, request, *args, **kwargs):
        user = self._get_user(username)

        if not user:
            return False
        if user.correct_password(password):
            request.user = user.email
            return True
        return False

    def _get_client(self, client_id: str):
        try:
            return self._registry(domain.Client).find(client_id) #! changed from iam.Client to domain.Client
        except Exception as e:
            if e.__str__() == 'near ".": syntax error':
                return None
            raise e

    def _get_user(self, username: str):
        return self._registry(domain.User).find( #! changed from iam.User to domain.User
            lambda x: (x.email == username) | (x.preferred_username == username)#! changed from iam.User.c to domain.User
        )

    def _get_bearer_token(self, token: str, token_type_hint: str = None):
        access_criteria = lambda x: (x.access_token == token)
        refresh_criteria = lambda x: (x.refresh_token == token)

        current_token_type = 0
        criteria = [access_criteria, refresh_criteria]
        if token_type_hint == self._valid_token_type_hints[1]:
            current_token_type = 1

        bearer_token = self._registry(domain.BearerToken).find(criteria[current_token_type]) #? Does a find need to be implemented? This could be refresh or access. Could pass in type of token
        token_type = self._valid_token_type_hints[current_token_type]

        if not bearer_token:
            current_token_type = (current_token_type + 1) % 2
            bearer_token = self._registry(domain.BearerToken).find(criteria[current_token_type])
            token_type = self._valid_token_type_hints[current_token_type]

        return [bearer_token, token_type]

    def _get_authorization_code(self, code):
        code_str = code if isinstance(code, str) else code['code'] if isinstance(code, dict) else code.code
        return self._registry(domain.AuthorizationCode).find((domain.AuthorizationCode.code == code_str)) if isinstance(code_str, str) else code

    def _http_basic_authentication(self, request):
        try:
            client_id, client_secret = self._get_basic_auth(request)
        except ValueError:
            return False

        client = self._get_client(client_id)
        
        if not client:
            return False

        if client.validate_client_secret(client_secret): #! DO MORE
            request.client = client
            return True
        return False
        #! WHAT TO DO FROM HERE?!

    def _get_basic_auth(self, request):
        auth_string = self._get_basic_auth_string(request)
        if not auth_string:
            return None
        
        try:
            encoding_type = request.encoding or 'utf-8'
        except:
            encoding_type = 'utf-8'

        try:
            b64_decoded = base64.b64decode(auth_string)
        except TypeError:
            return None

        try:
            decoded_string = b64_decoded.decode(encoding_type)
        except UnicodeDecodeError:
            return None

        try:
            return map(unquote_plus, decoded_string.split(':', 1)) #Is it client secret instead?
        except ValueError:
            return None

    def _get_basic_auth_string(self, request):
        auth = request.headers.get('Authorization') #! Is it named differently?

        if not auth:
            return None

        split_auth = auth.split(' ')
        if len(split_auth) != 2:
            return None
        auth_type, auth_string = split_auth

        if auth_type != 'Basic':
            return None
        
        return auth_string

    def _http_headers_authentication(self, request):
        user = request.body['username']
        client = self._registry(domain.Client).find( #! changed from iam.User to domain.User
            (domain.Client.user.email == user) | (domain.Client.user.preferred_username == user) #! changed from iam.User.c to domain.User
        )

        if not client:
            return False
        if client.user.correct_password(request.body['password']):
            request.client = client
            return True
        return False

    @staticmethod
    def _generate_bearer_token(token, request):
        return domain.BearerToken(
            client=request.client,
            user=request.user,
            scopes=request.scopes,
            access_token=token['access_token'],
            expires_at=datetime.utcnow() + timedelta(seconds=token.expires_in),
            refresh_token=token['refresh_token'],
            token_type=token['token_type'],
        )

    @staticmethod
    def _generate_authorization_code(code, request, claims):
        return domain.AuthorizationCode(
            client=request.client,
            user=request.user,
            scopes=request.scopes,
            code=code['code'],
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            redirect_uri=request.redirect_uri,
            challenge=request.code_challenge,
            challenge_method=request.code_challenge_method,
            claims=claims,
            )

    @staticmethod
    def _generate_introspection_response(bearer_token, token_type):
        #! Needs more work??
        is_active = bearer_token.validate_access_token() if token_type == 'access_token' else bearer_token.validate_refresh_token()
        jti = bearer_token.access_token if token_type == 'access_token' else bearer_token.refresh_token
        resp = {
            'active': is_active,
            'scope': bearer_token.scope,
            'client_id': bearer_token.client.client_id,
            'username': bearer_token.user.email or bearer_token.user.prefered_username, #use whichever one isn't None
            'token_type': token_type,
            'exp': bearer_token.expires_at.timestamp(),
            'iat': bearer_token.created_at.timestamp(),
            'nbf': bearer_token.activates_at.timestamp(),
            'sub': bearer_token.user.sub, #????????? user? bearer_token.user.
            'aud': bearer_token.client.client_id, #????????? client? #!Is this right? 
            'iss': 'https://app.pwrlab.com/', #!!!! double check
            'jti': jti, #!! JWT string, LOOK MORE INTO
        } if bearer_token else None

        return resp


class IamRequestValidator(domain.RequestValidator): #does this need to inherit?
    def __init__(self, validator: OauthlibRequestValidator):
        self._server = Server(
            validator, #need to make sure this is instantiated
            token_generator=tokens.signed_token_generator(
                os.environ['PRIVATE_PEM_KEY'],
                issuer="PwrLab"
            ),
            refresh_token_generator=tokens.signed_token_generator(
                os.environ['PRIVATE_PEM_KEY'],
                issuer="PwrLab"
            ),
        )

    def validate_pre_auth_request(self, request: ff.Message):
        http_request = request.headers.get('http_request')
        return self._server.validate_authorization_request(
            f'{http_request["headers"]["Host"]}{http_request["url"]}',
            http_request['method'],
            '',
            http_request['headers']
        )

    def create_token_response(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        headers, body, status = self._server.create_token_response(uri, http_method, body, headers)

    def validate_post_auth_request(self, request: ff.Message):
        pass

    def create_response(self, request: ff.Message):
        uri, http_method, body, headers = self._get_request_params(request)
        return self._server.create_authorization_response(
            uri, http_method, body, headers
        )

    def verify_request(self, request: ff.Message, scopes):
        uri, http_method, body, headers = self._get_request_params(request)
        is_valid, req = self._server.verify_request(uri, http_method, body, headers, scopes=scopes)
        return is_valid, req
        pass

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