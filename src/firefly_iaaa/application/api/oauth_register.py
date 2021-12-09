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


@ff.rest('/iaaa/register', method='POST', tags=['public'], secured=False)
class OAuthRegister(GenericOauthIamEndpoint):
    _oauth_register: domain.OAuthRegister = None

    def __call__(self, **kwargs):
        self.info('Registering User')
        print('KWARGS coming into OauthRegister API', kwargs)
        print(type(kwargs['_message']))
        print(dir(kwargs['_message']))
        print(kwargs['_message'].__dict__)
        if 'username' not in kwargs or 'password' not in kwargs:
            raise Exception('Missing username/password')
        resp = self._oauth_register(kwargs)
        if 'error' in resp:
            return resp
        return self._make_local_response(resp[1], resp[0])
