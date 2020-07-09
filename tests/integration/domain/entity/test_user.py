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
import uuid

from iam import User


def test_create_user(system_bus, registry):
    id_ = str(uuid.uuid1())
    system_bus.invoke('iam.CreateUser', {
        'sub': id_,
        'password': 'abc123',
    })
    assert len(registry(User).find_all_matching(User.c.sub == id_)) == 1


def test_authenticate_without_validation(system_bus):
    system_bus.invoke('iam.CreateUser', {
        'sub': str(uuid.uuid1()),
        'username': 'user',
        'password': ''
    })
