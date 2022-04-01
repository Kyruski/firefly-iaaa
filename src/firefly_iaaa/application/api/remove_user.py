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
from firefly_iaaa.application.api.generic_endpoint import GenericEndpoint


@ff.rest('/iaaa/delete', method='POST', tags=['public'])
class RemoveUser(GenericEndpoint):
    _kernel: ff.Kernel = None
    _remove_user: domain.RemoveUser = None

    def __call__(self, user_id: str, **kwargs):
        self._kernel.reject_missing_tenant()
        if self._kernel.user.token['sub'] == user_id:
            return self._remove_user(user_id)
        return {'status': 'failure', 'message': 'mismatching user_id and token sub'}
