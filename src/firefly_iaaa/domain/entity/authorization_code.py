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

from datetime import datetime
from typing import List

import firefly as ff
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User
from firefly_iaaa.domain.entity.scope import Scope


class AuthorizationCode(ff.AggregateRoot):
    id_: str = ff.id_()
    client: Client = ff.required(index=True)
    user: User = ff.required()
    scopes: List[Scope] = ff.list_()
    redirect_uri: str = ff.optional()
    claims: dict = ff.optional()
    code: str = ff.required(str, length=36, index=True)
    expires_at: datetime = ff.required()
    state: str = ff.required()
    challenge: str = ff.optional(str, length=128)
    challenge_method: str = ff.optional(validators=[ff.IsOneOf(('S256', 'plain'))])
    claims: dict = ff.optional()
    verifier: str = ff.optional()
    is_valid: bool = True

    def validate_redirect_uri(self, redirect_uri: str):
        return self.redirect_uri == redirect_uri

    def invalidate(self):
        self.is_valid = False

    def is_expired(self):
        return self.expires_at < datetime.utcnow()

    def validate(self, client_id: str):
        return self.is_valid and client_id == self.client.client_id and not self.is_expired()

    def get_scopes(self):
        return [scope.id for scope in self.scopes]
