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
from typing import Any
import firefly as ff
from datetime import datetime, timedelta


class MockCache(ff.Cache):
    _storage: dict = {}

    def set(self, key: str, value: Any, ttl: int = None, **kwargs):
        time = (datetime.now() + timedelta(seconds=ttl)) if ttl else None
        self._storage[key] = {'value': value, 'ttl': time}
    
    def get(self, key: str, **kwargs):
        item = self._storage.get(key)
        if not item:
            return None
        if item['ttl'] is None or datetime.now() < item['ttl']:
            return item['value']
        return None

    def delete(self, key: str, **kwargs):
        self._storage[key] = None
        del self._storage[key]
        return None

    def clear(self, **kwargs):
        return None

    def increment(self, key: str, amount: int = 1, **kwargs) -> Any:
        return None

    def decrement(self, key: str, amount: int = 1, **kwargs) -> Any:
        return None

    def add(self, key: str, value: Any, **kwargs) -> Any:
        return None

    def remove(self, key: str, value: Any, **kwargs) -> Any:
        return None

    def list(self):
        return self._storage.items()