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
from firefly_iaaa.application.api.generic_endpoint import GenericEndpoint


@ff.rest('/iaaa/change-password', method='POST', tags=['public'], secured=False)
class ChangePassword(GenericEndpoint):
    _cache: ff.Cache = None

    def __call__(self, **kwargs):
        self.debug('Changing password for User')
        try:
            request_id = kwargs['request_id']
            payload = self._cache.get(request_id)
            if not payload:
                return self._make_error_response('Password request is invalid')
            if payload['message'] == 'reset':
                username = payload['username'].lower()
            new_password = kwargs['new_password']
        except KeyError as e:
            return self._make_error_response('Missing password')

        found_user: domain.User = self._registry(domain.User).find(lambda x: (x.email.lower() == username) & (x.deleted_at.is_none()))

        if found_user:
            found_user.change_password(new_password)
            self.debug('Password Successfully Changed')
            self._cache.delete(request_id)
            return self._make_response()
        return self._make_error_response('No User found')
