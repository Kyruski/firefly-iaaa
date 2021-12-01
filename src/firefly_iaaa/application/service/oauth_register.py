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
import uuid
from firefly_iaaa.application.service.generic_oauth_endpoint import GenericOauthEndpoint
import firefly_iaaa.domain as domain


@ff.rest('/iaaa/register', method='POST', tags=['public'])
class OAuthRegister(GenericOauthEndpoint):

    def __call__(self, **kwargs):
        self.debug('Registering User')
        try:
            username = kwargs['username']
            password = kwargs['password']
        except KeyError:
            raise Exception('Missing username/password')

        found_user = self._registry(domain.User).find(lambda x: x.email == username)

        if found_user:
            return {'error': 'User already exists'}

        self.create_entities(username, password)
        kwargs['grant_type'] = 'password'

        return self.invoke('firefly_iaaa.OAuthLogin', kwargs, async_=False)


    def create_entities(self, username: str, password: str):
        new_tenant = domain.Tenant(name=f'user_tenant_{username}')
        self._registry(domain.Tenant).append(new_tenant)


        new_user = domain.User.create(email=username, password=password, tenant=new_tenant)
        self._registry(domain.User).append(new_user)

        new_client = domain.Client.create(
            tenant=new_tenant,
            name=username,
            grant_type='password',
            scopes=['full_access'],
            client_secret=uuid.uuid4(),
        )
        self._registry(domain.Client).append(new_client)
