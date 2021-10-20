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

@ff.query_handler('iaaa.GetClientUserAndToken')
class GetClientUserAndToken(ff.ApplicationService):
    _registry: ff.Registry = None
    _oauth_provider: domain.OauthProvider = None

    def __call__(self, token, user_id):
        user = self._registry(domain.User).find(lambda x: x.sub == user_id)
        if user:
            client = self._registry(domain.Client).find(lambda x: x.tenant_id == user.tenant_id)
            client_id = client.client_id
        decoded = self._oauth_provider.decode_token(token, client_id)

        return {
            'decoded': decoded,
            'user': user,
            'client_id': client_id,
        }
