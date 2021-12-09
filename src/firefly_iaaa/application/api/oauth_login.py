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
from firefly_iaaa.application.api.generic_oauth_iam_endpoint import GenericOauthIamEndpoint
import firefly_iaaa.domain as domain


@ff.rest('/iaaa/login', method='POST', tags=['public'], secure=False)
class OAuthLogin(GenericOauthIamEndpoint):
    _oauth_login: domain.OAuthLogin = None

    def __call__(self, **kwargs):
        self.debug('Logging in with In-House')

        try:
            username = kwargs['username']
            password = kwargs['password']
        except KeyError:
            raise Exception('Missing email/password')

        headers, body = self._oauth_login(kwargs)
        if not body:
            raise ff.UnauthenticatedError()

        return self._make_local_response(body, headers)
