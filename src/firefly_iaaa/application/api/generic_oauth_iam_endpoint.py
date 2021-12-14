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

from firefly_iaaa.application.api.generic_oauth_endpoint import GenericOauthEndpoint


class GenericOauthIamEndpoint(GenericOauthEndpoint):

    def __call__(self, **kwargs):
        pass

    def _make_local_response(self, headers, body):
        tokens = body.get('tokens')
        cookies = []
        access_cookie = {
            'name': 'accessToken',
            'value': tokens['access_token'],
            'httponly': True,
            'max_age': tokens['expires_in'],
        }
        cookies.append(access_cookie)
        if 'refresh_token' in tokens:
            refresh_cookie = {
                'name': 'refreshToken',
                'value': tokens['refresh_token'],
                'httponly': True,
            }
            cookies.append(refresh_cookie)
        envelope = self._make_response(tokens, headers=headers, cookies=cookies)
        return envelope
