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

import importlib

import firefly as ff
from firefly_iaaa.application.api.generic_oauth_iam_endpoint import GenericOauthIamEndpoint
import firefly_iaaa.domain as domain


@ff.rest('/iaaa/register', method='POST', tags=['public'], secured=False)
class OAuthRegister(GenericOauthIamEndpoint):
    _oauth_register: domain.OAuthRegister = None
    _context_map: ff.ContextMap = None
    _context: str = None

    def __call__(self, **kwargs):
        self.info('Registering User')
        kwargs = self._fix_email(kwargs)
        if 'username' not in kwargs or 'password' not in kwargs:
            return self._make_error_response('Missing username/password')
        resp = self._oauth_register(kwargs)
        try:
            if 'error' in resp:
                return self._make_error_response(resp)
        except TypeError:
            pass

        return resp
