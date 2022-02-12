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



class BearerToken(ff.AggregateRoot):
    id_: str = ff.id_()
    client: Client = ff.required(index=True)
    user: User = ff.required(index=True)
    scopes: List[Scope] = ff.list_()
    access_token: str = ff.required(str, length=36, index=True)
    refresh_token: str = ff.required(str, length=36, index=True)
    expires_at: datetime = ff.required()
    refresh_expires_at: datetime = ff.optional()
    created_at: datetime = ff.now()
    activates_at: datetime = ff.optional(default=datetime.utcnow())
    token_type: str = ff.optional(default='Bearer')
    claims: dict = ff.optional()
    is_access_valid: bool = True
    is_valid: bool = True

    def validate_scopes(self, scopes: List[str]):
        if not scopes:
            return False
        for scope in scopes:
            if scope not in self.get_scopes():
                return False
        return True

    def validate_access_token(self, access_token: str, client: Client):
        return self.access_token == access_token and self.is_access_valid and self._check_active() and self.client.client_id == client.client_id

    def validate_refresh_token(self, refresh_token: str, client: Client):
        return self.refresh_token == refresh_token and self.is_valid and self._check_refresh_active() and self.client == client

    def validate(self, scopes: List[str]):
        return self.token_type.lower() == 'bearer' and self.is_valid and self.validate_scopes(scopes) and self.is_access_valid and self._check_active()

    def invalidate_access_token(self):
        self.is_access_valid = False

    def invalidate(self):
        self.invalidate_access_token()
        self.is_valid = False

    def _has_refresh_expired(self):
        return self.refresh_expires_at < datetime.utcnow() if self.refresh_expires_at is not None else False

    def _has_expired(self):
        return self.expires_at < datetime.utcnow() if self.expires_at is not None else False

    def _has_activated(self):
        return self.activates_at < datetime.utcnow()

    def _check_active(self):
        return self._has_activated() and not self._has_expired()

    def _check_refresh_active(self):
        return self._has_activated() and not self._has_refresh_expired()

    def get_scopes(self):
        return [scope.id for scope in self.scopes]
