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


class GenericOauthMiddleware(ff.Handler, ff.LoggerAware, ff.SystemBusAware):
    _kernel: ff.Kernel = None
    _oauth_provider: domain.OauthProvider = None
    _get_client_user_and_token: domain.GetClientUserAndToken = None

    def handle(self, message: ff.Message):
        pass

    def _retrieve_token_from_http_request(self):
        for k, v in self._kernel.http_request['headers'].items():
            if k.lower() == 'authorization':
                if not v.lower().startswith('bearer'):
                    raise ff.UnauthorizedError()
                return v
        return None

    def _fix_email(self, message):
        if message.username:
            message.username = message.username.lower()
        message.email = (message.email or message.username).lower()
        return message
