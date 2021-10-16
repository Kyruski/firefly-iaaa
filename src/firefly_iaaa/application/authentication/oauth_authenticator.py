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

from typing import Optional

import firefly as ff
import firefly_iaaa.infrastructure as infra
from jwt import InvalidTokenError


@ff.authenticator()
class OAuthAuthenticator(ff.Handler):
    # _jwt_service: domain.JwtService = None
    _kernel: ff.Kernel = None
    _oauth_provider: infra.OauthProvider = None

    def handle(self, message: ff.Message, *args, **kwargs):
        if self._kernel.http_request and self._kernel.secured:
            token = None
            for k, v in self._kernel.http_request['headers'].items():
                if k.lower() == 'authorization':
                    if not v.lower().startswith('bearer'):
                        raise ff.UnauthenticatedError()
                    token = v.split(' ')[-1]
            if token is None:
                raise ff.UnauthenticatedError()

            try:
                decoded = self._oauth_provider.decode(token)
                # print(decoded)
                if decoded is None:
                    raise ff.UnauthenticatedError()
            except InvalidTokenError:
                raise ff.UnauthenticatedError()
            
            # if not self.request_validator.authenticate_client(message):
            #     raise ff.UnauthenticatedError()

            self._kernel.user.token = decoded
            self._kernel.user.scopes = decoded['scopes']
            return True

        return self._kernel.secured is not True
