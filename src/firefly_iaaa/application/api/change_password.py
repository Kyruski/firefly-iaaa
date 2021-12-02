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


@ff.rest('/iaaa/change-password', method='POST', tags=['public'])
class ChangePassword(ff.ApplicationService):
    _registry: ff.Registry = None

    def __call__(self, **kwargs):
        self.debug('Changing password for User')
        try:
            username = kwargs['username']
            old_password = kwargs['old_password']
            new_password = kwargs['new_password']
        except KeyError:
            raise Exception('Missing username/password')

        found_user: domain.User = self._registry(domain.User).find(lambda x: x.email == username)
        print('aaaaaaaaaaa', username, old_password, new_password, found_user)
        if found_user:
            if found_user.correct_password(old_password):
                found_user.change_password(new_password)
                self.debug('Password Successfully Changed')
                return True
            raise Exception('Incorrect password for User')
        raise Exception('No User with matching password')
