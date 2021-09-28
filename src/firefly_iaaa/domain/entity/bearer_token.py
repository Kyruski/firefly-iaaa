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



class BearerToken(ff.Entity):
    client: Client = ff.required()
    user: User = ff.required()
    scopes: List[str] = ff.required()
    access_token: str = ff.required(str, length=36)
    refresh_token: str = ff.required(str, length=36)
    expires_at: datetime = ff.required()
    refresh_expires_at: datetime = ff.optional()
    created_at: datetime = ff.now()
    activates_at: datetime = ff.optional(default=datetime.utcnow())
    token_type: str = ff.optional(default='Bearer')
    is_access_valid: bool = True
    is_valid: bool = True

    def validate_scopes(self, scopes: List[str]):
        for scope in scopes:
            if scope not in self.scopes:
                return False
        return True

    def validate_access_token(self, access_token: str, client: domain.Client):
        return self.access_token == access_token and self.is_access_valid and self._check_active(self.expires_at) and self.client == client

    def validate_refresh_token(self, refresh_token: str, client: domain.Client):
        return self.refresh_token == refresh_token and self.is_valid and self._check_active(self.expires_at) and self.client == client

    def validate(self, scopes: List[str]):
        return self.token_type == 'Bearer' and self.is_valid and self.validate_scopes(scopes) and self.validate_access_token() and self.validate_refresh_token()

    def invalidate_access_token(self):
        self.is_access_valid = False

    def invalidate(self):
        self.invalidate_access_token()
        self.is_valid = False

    def generate_new_token(self):
        return #!!!!

    def _has_expired(expires_at):
        return expires_at < datetime.utcnow() if expires_at is not None else False

    def _has_activated(self):
        return self.activates_at < datetime.utcnow() if self.activates_at else True

    def _check_active(self, expires_at):
        return self._has_activated() and not self._has_expired(expires_at)
