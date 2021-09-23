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

from datetime import datetime, timedelta
import uuid

import firefly as ff


class Token(ff.Entity):
    token: str = ff.required(str, length=36)
    expires_at: datetime = ff.required()
    token_type: str = ff.required(validators=[ff.IsOneOf(('access_token', 'refresh_token', 'authorization_code', 'invalid'))])

    EXPIRATION_TIMEDELTAS: dict = {
        'access_token': timedelta(hours=60),
        'authorization_code': timedelta(minutes=10),
        'refresh_token': timedelta(year=100),
    }

    def validate(self, token: str):
        if self.EXPIRATION_TIMEDELTAS.get(self.token_type)
        return self.token == token and self.token_type != 'invalid' and not self._has_expired()

    def invalidate(self):
        self.is_valid = False

    def generate_new_token(self):
        # if not self.validate():
        #     return None
        _token = str(uuid.uuid4())
        _expires_at = self._generate_expiration_date()

        new_token = Token(token=_token, expires_at=_expires_at, token_type=self.token_type)
        self.invalidate_token()

        return new_token

    def _get_timedelta(self):
        return self.EXPIRATION_TIMEDELTAS.get(self.token_type)

    def _generate_expiration_date(self):
        time_delta = self._get_timedelta()
        if time_delta:
            return datetime.utcnow() + time_delta
        return None
    
    def _has_expired(self):
        return self.expires_at < datetime.utcnow() if self.expires_at is not None else False
