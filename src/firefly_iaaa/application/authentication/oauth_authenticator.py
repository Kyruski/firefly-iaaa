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
import firefly_iaaa.domain as domain
from jwt import InvalidTokenError


@ff.authenticator()
class OAuthAuthenticator(ff.Handler, ff.LoggerAware, ff.SystemBusAware):
    # _jwt_service: domain.JwtService = None
    _kernel: ff.Kernel = None
    _oauth_provider: domain.OauthProvider = None
    _request_validator: domain.OauthRequestValidators = None

    def handle(self, message: ff.Message, *args, **kwargs):
        self.debug('Authenticating with Cognito')
        self.debug(self._kernel)
        if self._kernel.http_request and self._kernel.secured:
            token = None
            for k, v in self._kernel.http_request['headers'].items():
                if k.lower() == 'authorization':
                    if not v.lower().startswith('bearer'):
                        print('abc1')
                        raise ff.UnauthenticatedError()
                    token = v.split(' ')[-1]
            if token is None:
                try:
                    token = message.access_token
                except:
                    print('abc2')
                    raise ff.UnauthenticatedError()

            self.debug('Decoding token')
            try:
                resp = self.request('iaaa.GetClientUserAndToken', data={'token': token, 'user_id': self._kernel.user.id})
                decoded= resp['decoded']
                user = resp['user']
                client_id = resp['client_id']
            except:
                print('abc3')
                raise ff.UnauthenticatedError()
            # client_id = self._kernel.user.id
            # if not user:
            #     raise ff.UnauthenticatedError()
            # # if user:
            # client = self.request('iaaa.Client', lambda x: x.tenant_id == user.tenant_id)
            # client_id = client.client_id
            # try:
            #     decoded = self._oauth_provider.decode_token(token, client_id) #!USE CLIENT ID
            #     if decoded is None:
            #         raise ff.UnauthenticatedError()
            #     self.debug('Result from decode: %s', decoded)
            # except InvalidTokenError as e:
            #     raise ff.UnauthenticatedError()
            
    
            self._kernel.user.token = decoded
            self._kernel.user.scopes = decoded['scope'].split(' ')
            return True
        return self._kernel.secured is not True
