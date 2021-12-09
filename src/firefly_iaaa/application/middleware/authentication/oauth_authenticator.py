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


@ff.authenticator()
class OAuthAuthenticator(GenericOauthMiddleware):
    _request_validator: domain.OauthRequestValidators = None

    def handle(self, message: ff.Message, *args, **kwargs):
        self.info('Authenticating')
        self.info(self._kernel)
        if self._kernel.http_request and self._kernel.secured:
            token = self._retrieve_token_from_http_request()
            if token:
                token = token.split(' ')[-1]
            if token is None:
                try:
                    token = message.access_token
                except:
                    raise ff.UnauthenticatedError()

            self.debug('Decoding token')
            try:
                resp = self._get_client_user_and_token(token, self._kernel.user.id)
                decoded= resp['decoded']
                user = resp['user']
                client_id = resp['client_id']
            except:
                raise ff.UnauthenticatedError()
    
            self._kernel.user.token = decoded
            self._kernel.user.scopes = decoded['scope'].split(' ')
            return True
        return self._kernel.secured is not True
