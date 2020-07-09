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

authorization_code = 'Authorization Code'
implicit = 'Implicit'
resource_owner_password_credentials = 'Resource Owner Password Credentials'
client_credentials = 'Client Credentials'


def response_type_choices(client_dto: dict):
    if client_dto['grant_type'] == authorization_code:
        return 'code token', 'code id_token', 'code token id_token'
    if client_dto['grant_type'] == implicit:
        return 'id_token token', 'id_token'

    return ()


class Client(ff.AggregateRoot):
    id: str = ff.id_()
    name: str = ff.required(str)
    grant_type: str = ff.required(str, validators=[ff.IsOneOf((
        authorization_code, implicit, resource_owner_password_credentials, client_credentials
    ))])
    response_type: str = ff.optional(str, validators=[ff.IsOneOf(response_type_choices)])
    scopes: str = ff.required(str)
    default_redirect_uri: str = ff.required(str)
    redirect_uris: List[str] = ff.list_()
    allowed_response_types: List[str] = ff.list_(validators=[ff.IsOneOf(('code', 'token'))])

    def validate_redirect_uri(self, redirect_uri: str):
        return redirect_uri in self.redirect_uris

    def validate_response_type(self, response_type: str):
        return response_type in self.allowed_response_types

    def validate_scopes(self, scopes: List[str]):
        for scope in scopes:
            if scope not in self.scopes:
                return False
        return True
