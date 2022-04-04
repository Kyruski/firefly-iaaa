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
import bcrypt

import firefly as ff
import firefly_iaaa.domain as domain


class OAuthLogin(ff.DomainService, ff.LoggerAware):
    _cognito_login: domain.CognitoLogin = None
    _registry: ff.Registry = None
    _oauth_register: domain.OAuthRegister = None
    _create_token: domain.CreateToken = None

    def __call__(self, passed_in_kwargs: dict):
        self.debug('Logging in with In-House')
        username = passed_in_kwargs['username']
        password = passed_in_kwargs['password']
        tokens = [None, None]

        found_user: domain.User = self._registry(domain.User).find(lambda x: (x.email.lower() == username) & (x.deleted_at.is_none()))
        if found_user:
            passed_in_kwargs['grant_type'] = 'password'
            self.info('We found a user, trying to login with password')
            if found_user.correct_password(password):
                resp = self._get_tokens(found_user, passed_in_kwargs)
            else:
                self.info('User password incorrect, trying Cognito')
                resp = self._try_cognito(username, password, found_user, passed_in_kwargs)
                if resp is None:
                    raise ff.UnauthenticatedError('Incorrect username/password combination')
        else:
            raise ff.NotFound()

        if resp is None:
            raise ff.NotFound()

        return resp

    def _try_cognito(self, username: str, password: str, user: domain.User, passed_in_kwargs: dict):
        self.debug('Switching to Cognito Log in')
        try:
            resp = self._cognito_login(username, password) #data has tokens and idToken
            message, error, success, _ = resp.values()
            if error:
                if message:
                    ff.UnauthenticatedError(message)
                else:
                    ff.UnauthenticatedError(error)
            if success:
                resp = self._add_cognito_user(password, user, passed_in_kwargs)
                return resp
        except Exception as e:
            raise ff.UnauthenticatedError() from e

    def _add_cognito_user(self, password: str, user: domain.User, passed_in_kwargs):
        self.debug('Transfering Cognito user to In-House user')
        user.salt = bcrypt.gensalt().decode()
        user.change_password(password)
        resp = self._get_tokens(user, passed_in_kwargs)
        if resp[1]['tokens']:
            return resp
        raise Exception('Something went wrong')

    def _get_tokens(self, user: domain.User, passed_in_kwargs: dict):
        passed_in_kwargs = self._set_client_id(user, passed_in_kwargs)
        resp = self._create_token(passed_in_kwargs)
        return [resp[0], {'tokens': resp[1], 'user': user.generate_scrubbed_user()}]

    def _set_client_id(self, found_user, kwargs):
        if not kwargs.get('client_id'):
            if found_user.tenant_id is not None:
                user_client = self._registry(domain.Client).find(lambda x: x.tenant_id == found_user.tenant_id)
                kwargs['client_id'] = user_client.client_id
            else:
                kwargs['client_id'] = 'bac2ee04-a141-4c1c-9b7f-9f120bb63935'
                found_user.tenant_id = 'f0803c4d-fa1a-4d1f-b6c6-7479d2212a54'
                found_user.tenant = self._registry(domain.Tenant).find(found_user.tenant_id)
        return kwargs

    def _set_referer(self, kwargs: dict):
        headers = {
            'http_request': {
                'headers': {
                    'Referer': 'https://www.pwrlab.com/'
                }
            }
        }
        if not kwargs.get('headers'):
            kwargs['headers'] = headers
        elif not kwargs['headers'].get('http_request'):
            kwargs['headers']['http_request'] = headers['http_request']
        elif not kwargs['headers']['http_request'].get('headers'):
            kwargs['headers']['http_request']['headers'] = headers['http_request']['headers']
        elif not kwargs['headers']['http_request']['headers'].get('Referer'):
            kwargs['headers']['http_request']['headers']['Referer'] = headers['http_request']['headers']['Referer']
        return kwargs
