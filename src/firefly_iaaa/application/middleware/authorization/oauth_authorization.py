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
from firefly_iaaa.application.middleware.generic_oauth_middleware import GenericOauthMiddleware
import firefly_iaaa.domain as domain


class AuthorizeRequest(GenericOauthMiddleware):
    _registry: ff.Registry = None

    def handle(self, message: ff.Message):
        print('aaafff', self._kernel)
        print('aaaaaaaaaaaaaaaaaaaattt', message.__dict__)
        token = None
        message = self._fix_email(message)
        try:
            if not message.access_token:
                token = self._get_token()
                if not token:
                    return False
                message.access_token = token
            else:
                token = message.access_token
        except AttributeError:
            token = self._get_token()
            if not token:
                return False
            message.access_token = token
        if not message.access_token and not token:
            return False
        if message.access_token.lower().startswith('bearer'):
            message.access_token = message.access_token.split(' ')[-1]

        try:
            resp = self._get_client_user_and_token(token, self._kernel.user.id)
            decoded= resp['decoded']
            user = resp['user']
            client_id = resp['client_id']
        except:
            raise ff.UnauthorizedError()
        try:
            if not message.scopes:
                message.scopes = decoded.get('scope').split(' ') if decoded else self._kernel.user.scopes
        except AttributeError:
            message.scopes = decoded.get('scope').split(' ') if decoded else self._kernel.user.scopes

        message.token = message.access_token
        validated, resp = self._oauth_provider.verify_request(message, message.scopes)

        return validated

    def _get_token(self):
        token = None
        try:
            token = self._retrieve_token_from_http_request()
        except TypeError as e:
            if e.__str__().startswith("'NoneType'"):
                pass
            else:
                raise TypeError(e)
        if not token:
            try:
                token = self._kernel.user.token
            except Exception as e:
                raise(e)
        return token