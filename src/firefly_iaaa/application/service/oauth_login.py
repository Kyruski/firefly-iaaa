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
import json

import firefly as ff
from firefly_iaaa.application.service.create_token import OauthTokenCreationService
import firefly_iaaa.domain as domain

from firefly_iaaa.domain.entity.user import User


@ff.rest('/iaaa/authorization-request', method='POST', tags=['public'])
class OAuthLogin(OauthTokenCreationService):
    _cognito_login: domain.CognitoLogin = None

    def __call__(self, **kwargs):
        self.debug('Logging in with Native')
        username = kwargs.get('username')
        password = kwargs.get('password')

        found_user = self._registry(User).find(lambda x: x.email == username)
        if found_user.correct_password(password):
            #loggedIn?
            return True
        else:
            user = self._try_cognito(username, password)
            if not isinstance(user, User):
                return False
        # THen what?
        # resp = self._get_tokens(kwargs)
        return True

    def _try_cognito(self, username: str, password: str):
        # if len(self._registry(User).find(lambda x: x.email == username)):
        if self._registry(User).find(lambda x: x.email == username) is None:
            try:
                message, error, success, data = self._cognito_login(username, password) #data has tokens and idToken
                if error:
                    if message:
                        ff.UnauthenticatedError(message)
                    else:
                        ff.UnauthenticatedError()
                if success:
                    user = self._transfer_cognito_user_to_native_user(username, password)
                    return user
            except:
                raise ff.UnauthenticatedError()
        else:
            raise ff.UnauthenticatedError('Incorrect Password')
        

    def _transfer_cognito_user_to_native_user(self, username: str, password: str):
        ## NEED SALT
        new_user = User.create(email=username, password=password)
        self._registry(User).append(new_user)
        return new_user

    # def _get_tokens(self, kwargs: dict):
    #     message = self._make_message(kwargs)

    #     headers, body, status =  self._oauth_provider.create_token_response(message)

    #     return json.loads(body)