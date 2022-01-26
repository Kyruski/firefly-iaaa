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
from firefly_iaaa.application.api.generic_oauth_iam_endpoint import GenericOauthIamEndpoint
import firefly_iaaa.domain as domain


@ff.rest('/iaaa/make-clients', method='POST', tags=['public'], secured=False)
class MakeBaseClients(GenericOauthIamEndpoint):
    _make_user: domain.MakeClientUserEntities = None

    def __call__(self, **kwargs):
        auth_no_pkce = {
            'username': 'fakeemail1@fake.com',
            'password': 'Abcd1234!',
            'tenant_name': 'testing_tenant_1',
            'name': 'Testing Tenant 1',
            'grant_type': 'authorization_code',
            'scopes': [],
            'default_redirect_uri': 'https://www.fake1.com',
            'redirect_uris': ['https://www.fake1.com', 'https://www.fake.com'],
            'roles': ['Connected Data Client'],
        }
        pkce = {
            'username': 'fakeemail2@fake.com',
            'password': 'Abcd1234!',
            'tenant_name': 'testing_tenant_2',
            'name': 'Testing Tenant 2',
            'grant_type': 'authorization_code_w_pkce',
            'scopes': [],
            'default_redirect_uri': 'https://www.fake2.com',
            'redirect_uris': ['https://www.fake2.com', 'https://www.fake.com'],
            'roles': ['Connected Data Client'],
        }
        client_cred = {
            'username': 'fakeemail3@fake.com',
            'password': 'Abcd1234!',
            'tenant_name': 'testing_tenant_3',
            'name': 'Testing Tenant 3',
            'grant_type': 'client_credentials',
            'scopes': [],
            'roles': ['Connected Data Client'],
        }
        self._make_user(**auth_no_pkce)
        self._make_user(**pkce)
        self._make_user(**client_cred)
        return True
