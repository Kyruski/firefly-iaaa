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

import secrets
import string

VALID_CHARACTERS = string.ascii_letters + string.digits


@ff.rest('/iaaa/reset-password', method='POST', tags=['public'])
class ResetPassword(ff.ApplicationService):
    _registry: ff.Registry = None

    def __call__(self, **kwargs):
        self.debug('Resetting Password for User')
        try:
            username = kwargs['username']
        except KeyError:
            raise Exception('Missing username/password')

        found_user: domain.User = self._registry(domain.User).find(lambda x: x.email == username)

        if found_user:
            new_password = ''.join(secrets.choice(VALID_CHARACTERS) for _ in range(16))
            found_user.change_password(new_password)
            self.debug('Password Successfully Reset')
            self.invoke('firefly_messaging.ResetPassword', {'password': new_password}, async_=False)#! FIRE EMAIL
            return True
        return False