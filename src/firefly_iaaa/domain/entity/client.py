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
import uuid

import firefly as ff
from .tenant import Tenant
from .role import Role
from .scope import Scope

authorization_code = 'authorization_code'
implicit = 'implicit'
resource_owner_password_credentials = 'password'
client_credentials = 'client_credentials'
refresh = 'refresh_token'


class Client(ff.AggregateRoot):
    id: str = ff.id_() 
    client_id: str = ff.optional(validators=[ff.HasLength(36)], index=True) # Needs to have 'client_id', should be same as sub if user/cleint combo
    external_id: str = ff.optional(index=True)
    name: str = ff.required()
    grant_type: str = ff.required(validators=[ff.IsOneOf((
        authorization_code, implicit, resource_owner_password_credentials, client_credentials, refresh
    ))])
    default_redirect_uri: str = ff.optional()
    redirect_uris: List[str] = ff.list_()
    scopes: List[Scope] = ff.list_()
    roles: List[Role] = ff.list_()
    allowed_response_types: List[str] = ff.list_(validators=[ff.IsOneOf(('code', 'token'))])
    uses_pkce: bool = ff.optional(default=True)
    client_secret: str = ff.optional(str, length=36)
    is_active: bool = True
    tenant: Tenant = ff.optional(index=True)
    tenant_id: str = ff.optional(index=True)

    @classmethod
    def create(cls, **kwargs):
        try:
            kwargs['tenant_id'] = kwargs['tenant'].id
        except KeyError:
            raise ff.MissingArgument('Tenant is a required field for Client::create()')
        try:
            kwargs['grant_type'] = kwargs['grant_type']
        except KeyError:
            raise ff.MissingArgument('Grant Type is a required field for Client::create()')
        if not kwargs.get('client_id'):
            kwargs['client_id'] = str(uuid.uuid4())
        kwargs['id'] = kwargs['client_id']
        return cls(**ff.build_argument_list(kwargs, cls))

    def validate_redirect_uri(self, redirect_uri: str):
        return redirect_uri in self.redirect_uris

    def validate_response_type(self, response_type: str):
        return response_type in self.allowed_response_types

    def validate_grant_type(self, grant_type: str):
        return grant_type in (self.grant_type, refresh)

    def validate_scopes(self, scopes: List[str]):
        client_scopes = self.get_scopes()
        if isinstance(scopes, str):
            scopes = scopes[1:-1].replace("'", '').replace(',', '').split(' ')
        #  Include ANY scopes
        # if not scopes:
        #     return False
        # for scope in scopes:
        #     if scope in client_scopes:
        #         return True
        # return False

        #  Include ALL scopes
        if not scopes:
            return False
        for scope in scopes:
            if scope not in client_scopes:
                return False
        return True

    def validate(self):
        return self.is_active

    def requires_pkce(self):
        return self.uses_pkce

    def is_confidential(self):
        return self.grant_type in (client_credentials, resource_owner_password_credentials) or \
            (self.grant_type == authorization_code and self.requires_pkce())

    def validate_client_secret(self, secret):
        return self.client_secret == secret

    def inactivate(self):
        self.is_active = False

    def add_role(self, role: Role):
        if isinstance(role, Role):
            self.roles.append(role)

    def generate_scrubbed_client(self):
        return {
            'client_id': self.client_id,
            'external_id': self.external_id,
            'name': self.name,
            'grant_type': self.grant_type,
            'default_redirect_uri': self.default_redirect_uri,
            'redirect_uris': self.redirect_uris,
            'scopes': self.get_scopes(),
            'allowed_response_types': self.allowed_response_types,
            'is_active': self.is_active,
            'tenant_id': self.tenant_id,
            'tenant_name': self.tenant.name,
        }

    def _get_entity_scopes(self):
        roles = [scope for role in self.roles for scope in role.scopes]
        roles += self.scopes
        return roles

    def get_scopes(self):
        return [scope.id for scope in self._get_entity_scopes()]

    def _get_scopes_from_roles(self):
        roles = []
        for role in self.roles:
            if isinstance(role, Role):
                roles.append(*role.scopes)
            else:
                roles.append(*role['scopes'])
        return roles
