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

from typing import List

import firefly as ff
import domain


class BearerToken(ff.Entity):
    client: domain.Client = ff.required()
    user: domain.User = ff.required()
    scopes: List[str] = ff.required()
    access_token: domain.Token = ff.required()
    refresh_token: domain.Token = ff.required()
    token_type: str = 'Bearer'
    # expires_at: datetime = ff.required()
    is_valid: bool = True
    # expiration_time: timedelta = None

    def validate_scopes(self, scopes: List[str]):
        for scope in scopes:
            if scope not in self.scopes:
                return False
        return True

    def validate_access_token(self, access_token: str, client: domain.Client):
        return self.access_token.validate(access_token)

    def validate_refresh_token(self, refresh_token: str, client: domain.Client):
        return self.refresh_token.validate(refresh_token)

    def validate(self, scopes: List[str]):
        return self.is_valid if self.validate_scopes(scopes) else False

    def invalidate_access_token(self):
        return self.access_token.invalidate()

    def invalidate_refresh_token(self):
        return self.refresh_token.invalidate()

    def invalidate(self):
        self.invalidate_access_token()
        self.invalidate_refresh_token()
        self.is_valid = False