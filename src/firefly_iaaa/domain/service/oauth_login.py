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
import os

import firefly as ff
import firefly_iaaa.domain as domain


class OAuthLogin(ff.DomainService):
    _cognito_login: domain.CognitoLogin = None
    _registry: ff.Registry = None
    _oauth_register: domain.OAuthRegister = None
    _create_token: domain.CreateToken = None

    def __call__(self, passed_in_kwargs: dict):
        self.debug('Logging in with In-House')
        username = passed_in_kwargs['username']
        password = passed_in_kwargs['password']
        tokens = [None, None]

        found_user = self._registry(domain.User).find(lambda x: x.email == username)

        if found_user:
            if found_user.correct_password(password):
                tokens = self._get_tokens(passed_in_kwargs)
        else:
            tokens = self._try_cognito(username, password)
        return tokens


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
        resp = self._oauth_register(data)
        if resp[1]:
            return resp
        raise Exception()

    def _get_tokens(self, kwargs: dict):
        if not kwargs['headers']['http_request']['headers'].get('Referer'):
            kwargs['headers']['http_request']['headers']['Referer'] = 'https://www.pwrlab.com/',
        resp = self._create_token(kwargs)
        return resp

    def _set_client_id(self, found_user, kwargs):
        user_client = self._registry(domain.Client).find(lambda x: x.tenant_id == found_user.tenant_id)
        kwargs['client_id'] = user_client.client_id
        return kwargs
