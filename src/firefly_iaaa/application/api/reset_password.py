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
import uuid

import firefly as ff
from firefly_iaaa import domain


@ff.rest('/iaaa/reset-password', method='POST', tags=['public'])
class ResetPassword(ff.ApplicationService):
    _registry: ff.Registry = None
    _cache: ff.Cache = None
    _subdomain: str = None

    def __call__(self, **kwargs):
        try:
            username = kwargs['username']
        except KeyError:
            raise Exception('Missing username/password')

        found_user = self._registry(domain.User).find(lambda x: x.email == username)
        if not found_user:
            return False

        cache_id = str(uuid.uuid4())
        self._cache.set(cache_id, value={'message': 'reset', 'username': username}, ttl=1800)
        reset_url = f'https://${self._subdomain}.pwrlab.com/change-password?request_id={cache_id}'

        try:
            self.invoke(
                'firefly_messaging.PasswordReset',
                {'reset_url': reset_url},
                async_=False
            )#! FIRE EMAIL
            return True
        except:
            return False
