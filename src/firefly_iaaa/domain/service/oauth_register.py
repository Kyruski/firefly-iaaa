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


class OAuthRegister(ff.DomainService):
    _oauth_login: domain.OAuthLogin = None
    _registry: ff.Registry = None
    _make_user: domain.MakeUser = None

    def __call__(self, passed_in_kwargs: dict):
        self.info('Registering User')
        print('KWARGS coming into OauthRegister domain', passed_in_kwargs)
        username = passed_in_kwargs['username']

        found_user = self._registry(domain.User).find(lambda x: x.email == username)

        if found_user:
            return {'error': 'User already exists'}

        passed_in_kwargs.update({
            'tenant_name': f'user_tenant_{username}',
            'grant_type': 'password',
            'scopes': ['full_access']
        })
        self._make_user(**passed_in_kwargs)
        return self._oauth_login(passed_in_kwargs)
