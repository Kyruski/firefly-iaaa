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
from typing import Dict

import firefly as ff
from firefly_iaaa.application.api.generic_oauth_endpoint import GenericOauthEndpoint
import firefly_iaaa.domain as domain


@ff.rest('/iaaa/login', method='POST', tags=['public'])
class OAuthLogin(GenericOauthEndpoint):
    _cognito_login: domain.CognitoLogin = None

    def __call__(self, **kwargs):
        self.debug('Logging in with In-House')
        try:
            username = kwargs['username']
            password = kwargs['password']
        except KeyError:
            raise Exception('Missing username/password')
        tokens = None

        found_user = self._registry(domain.User).find(lambda x: x.email == username)

        if found_user.correct_password(password):
            tokens = self._get_tokens(kwargs)
        else:
            tokens = self._try_cognito(username, password)

        # access_cookie = f"accessToken={tokens['access_token']}; HttpOnly; Max-Age={tokens['expires_in']}"
        # refresh_cookie = f"refreshToken={tokens['refresh_token']}; HttpOnly"

        # for k,v in tokens:
        #     cookie = f'Set-Cookie: {k}={v}'
        #     if k in ('access_token', 'refresh_token'):
        #         headers[f'Set-Cookie: {k}'] = v
        return self._make_response(tokens)

    def _try_cognito(self, username: str, password: str):
        self.debug('Switching to Cognito Log in')
        if self._registry(domain.User).find(lambda x: x.email == username) is None:
            try:
                message, error, success, data = self._cognito_login(username, password) #data has tokens and idToken
                if error:
                    if message:
                        ff.UnauthenticatedError(message)
                    else:
                        ff.UnauthenticatedError()
                if success:
                    user = self._transfer_cognito_user_to_native_user(username, password, data['decoded_id_token'])
                    return user
            except:
                raise ff.UnauthenticatedError()
        else:
            raise ff.UnauthenticatedError('Incorrect Password')
        

    def _transfer_cognito_user_to_native_user(self, username: str, password: str, data: Dict):
        self.debug('Transfering Cognito user to In-House user')
        data['email'] = username
        data['username'] = username
        data['password'] = password
        resp = self.invoke('firefly_iaaa.OAuthRegister', data)
        if resp.get('success'):
            return resp
        elif 'error' in resp:
            raise Exception(resp['error'])

    def _get_tokens(self, kwargs: dict):
        if not kwargs['headers']['http_request']['headers'].get('Referer'):
            kwargs['headers']['http_request']['headers']['Referer'] = 'https://www.pwrlab.com/',
        resp = self.invoke('firefly_iaaa.OauthTokenCreationService', kwargs, async_=False)
        return resp

    def _make_response(self, tokens):
        tokens.update({'message': 'success'})
        envelope = ff.Envelope.wrap(tokens)
        envelope = envelope.set_cookie(name='accessToken', value=tokens['access_token'], httponly=True, max_age=tokens['expires_in'])
        if 'refresh_token' in tokens:
            envelope = envelope.set_cookie(name='refreshToken', value=tokens['refresh_token'], httponly=True)
        return envelope
