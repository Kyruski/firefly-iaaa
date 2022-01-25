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
from .generic_oauth_middleware import GenericOauthDomainMiddleware


class OAuthAuthorizeRequest(GenericOauthDomainMiddleware):

    def __call__(self, message: ff.Message, **kwargs):
        print('aaafff', self._kernel)
        print('aaaaaaaaaaaaaaaaaaaattt', message.__dict__)
        print('a')
        token = None
        print('b')
        message = self._fix_email(message)
        print('c')
        try:
            print('d')
            if not message.access_token:
                print('e')
                token = self._get_token()
                print('f')
                if not token:
                    return False
                print('g')
                message.access_token = token
            else:
                print('h')
                token = message.access_token
        except AttributeError:
            print('i')
            token = self._get_token()
            print('j')
            if not token:
                print('k')
                return False
            print('l')
            message.access_token = token
        print('m')
        if not message.access_token and not token:
            print('n')
            return False
        print('o')
        if message.access_token.lower().startswith('bearer'):
            print('p')
            message.access_token = message.access_token.split(' ')[-1]
        print('q')

        print('r')
        try:
            print('s')
            decoded = self._decode_token(token, self._kernel.user.id)
        except:
            print('t')
            raise ff.UnauthorizedError()
        try:
            print('u')
            if not message.scopes:
                print('v')
                message.scopes = decoded.get('scope').split(' ') if decoded else self._kernel.user.scopes
        except AttributeError:
            print('w')
            message.scopes = decoded.get('scope').split(' ') if decoded else self._kernel.user.scopes

        print('x')
        message.token = message.access_token
        print('y', message.__dict__)
        validated, resp = self._oauth_provider.verify_request(message, message.scopes)
        print('z', validated)

        return validated

    def _get_token(self):
        token = None
        try:
            token = self._retrieve_token_from_http_request()
        except TypeError as e:
            if e.__str__().startswith("'NoneType'"):
                pass
            else:
                raise TypeError(e)
        if not token:
            try:
                token = self._kernel.user.token
            except Exception as e:
                raise(e)
        return token