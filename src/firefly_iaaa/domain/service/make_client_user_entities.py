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
import firefly_iaaa.domain as domain

class MakeClientUserEntities(ff.DomainService):
    _registry: ff.Registry = None

    def __call__(self, username: str, password: str, tenant_name: str, **kwargs):
        kwargs['email'] = kwargs.get('email', username)
        tenant = domain.Tenant(
            name=tenant_name
        )

        kwargs['tenant'] = tenant
        user = domain.User.create(
            username=username,
            password=password,
            **kwargs
        )

        kwargs['client_id'] = user.sub
        kwargs['name'] = kwargs.get('name', tenant_name)
        kwargs = self._make_params(user, username, kwargs)

        client = domain.Client.create(**kwargs)

        role = self._registry(domain.Role).find('fad2cf43-01df-44a1-bef4-0446d066e0bc')
        user.add_role(role)

        # Append at end to avoid appending before an error during entity creation
        self._registry(domain.Tenant).append(tenant)
        self._registry(domain.User).append(user)
        self._registry(domain.Client).append(client)

    def _make_params(self, kwargs: dict):

        self._validate_base_params(kwargs)
        grant_type = kwargs['grant_type']
        if grant_type == 'authorization_code':
            kwargs = self._add_auth_code_params(kwargs, False)
        elif grant_type == 'authorization_code_w_pkce':
            kwargs = self._add_auth_code_params(kwargs)
            kwargs['grant_type'] = 'authorization_code'
        elif grant_type == 'implicit':
            kwargs = self._add_auth_code_params(kwargs)
            kwargs['allowed_response_types'] = 'token'
        elif grant_type == 'client_secret':
            kwargs['client_secret'] = str(uuid.uuid4())
        elif grant_type != 'password':
            raise Exception('Invalid grant type')

        return kwargs

    def _validate_base_params(self, kwargs: dict):
        fields = ['scopes', 'grant_type']
        self._check_kwargs_for_fields(fields, kwargs)

    def _add_auth_code_params(self, kwargs: dict, uses_pkce: bool = True):
        fields = ['default_redirect_uri', 'redirect_uri']
        self._check_kwargs_for_fields(fields, kwargs)
        kwargs.update({
            'allowed_response_types': 'code',
            'uses_pkce': uses_pkce,
        })
        return kwargs

    def _check_kwargs_for_fields(self, fields, kwargs):
        for field in fields:
            if field not in kwargs:
                raise Exception(f'Missing required field: {field}')
