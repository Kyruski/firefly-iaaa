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
from .tenant import Tenant

authorization_code = 'authorization_code'
implicit = 'implicit'
resource_owner_password_credentials = 'password'
client_credentials = 'client_credentials'
refresh = 'refresh_token'


def response_type_choices(client_dto: dict):
    if client_dto['grant_type'] == authorization_code:
        return 'code token', 'code id_token', 'code token id_token'
    if client_dto['grant_type'] == implicit:
        return 'id_token token', 'id_token'

    return ()


class Client(ff.AggregateRoot):
    client_id: str = ff.id_() # Needs to be 'client_id'
    external_id: str = ff.optional(index=True)
    # user: User = ff.required(index=True)
    name: str = ff.required()
    grant_type: str = ff.required(validators=[ff.IsOneOf((
        authorization_code, implicit, resource_owner_password_credentials, client_credentials, refresh
    ))])
    # response_type: str = ff.optional(validators=[ff.IsOneOf(response_type_choices)]) #??
    default_redirect_uri: str = ff.optional()
    redirect_uris: List[str] = ff.list_()
    scopes: List[str] = ff.required()
    allowed_response_types: List[str] = ff.list_(validators=[ff.IsOneOf(('code', 'token'))])
    uses_pkce: bool = ff.optional(default=True)
    client_secret: str = ff.optional(str, length=36)
    is_active: bool = True
    tenant: Tenant = ff.optional() #in place of user?
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
        return cls(**ff.build_argument_list(kwargs, cls))

    def validate_redirect_uri(self, redirect_uri: str):
        return redirect_uri in self.redirect_uris

    def validate_response_type(self, response_type: str):
        return response_type in self.allowed_response_types

    def validate_grant_type(self, grant_type: str):
        return self.grant_type == grant_type or ((self.grant_type in (resource_owner_password_credentials, client_credentials) or (self.grant_type == authorization_code and not self.requires_pkce())) and grant_type == 'refresh_token')

    def validate_scopes(self, scopes: List[str]):
        if not scopes:
            return False
        for scope in scopes:
            if scope not in self.scopes:
                return False
        return True

    def validate(self):
        return self.is_active

    def requires_pkce(self):
        return self.uses_pkce

    def is_confidential(self): #might not be best
        return self.grant_type in (client_credentials, resource_owner_password_credentials) or \
            (self.grant_type == authorization_code and not self.requires_pkce())

    def validate_client_secret(self, secret):
        return self.client_secret == secret

    def inactivate(self):
        self.is_active = False

    def generate_scrubbed_client(self):
        return {
            'client_id': self.client_id,
            'external_id': self.external_id,
            'name': self.name,
            'grant_type': self.grant_type,
            'default_redirect_uri': self.default_redirect_uri,
            'redirect_uris': self.redirect_uris,
            'scopes': self.scopes,
            'allowed_response_types': self.allowed_response_types,
            'is_active': self.is_active,
            'tenant_id': self.tenant_id,
            'tenant_name': self.tenant.name,
        }
