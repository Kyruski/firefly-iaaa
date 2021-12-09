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
from typing import Dict

import firefly as ff
import uuid
from firefly_iaaa.application.api.generic_oauth_endpoint import GenericOauthEndpoint
import firefly_iaaa.domain as domain


@ff.rest('/iaaa/register', method='POST', tags=['public'])
class OAuthRegister(GenericOauthEndpoint):

    def __call__(self, **kwargs):
        self.info('Registering User')
        print('1')
        try:
            print('2')
            username = kwargs['username']
            password = kwargs['password']
        except KeyError:
            raise Exception('Missing username/password')

        print('3')
        found_user = self._registry(domain.User).find(lambda x: x.email == username)

        if found_user:
            return {'error': 'User already exists'}
        print('4')

        kwargs.update({
            'tenant_name': f'user_tenant_{username}',
            'grant_type': 'password',
            'scopes': ['full_access']
        })
        print('5')
        self.invoke('firefly_iaaa.MakeUserEntities', kwargs)
        print('6')
        return self.invoke('firefly_iaaa.OAuthLogin', kwargs, async_=False)
