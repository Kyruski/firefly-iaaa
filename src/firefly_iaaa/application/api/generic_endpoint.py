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
from typing import List, Union

import firefly as ff

from firefly_iaaa.domain.service.decode_token import DecodeToken


class GenericEndpoint(ff.ApplicationService):
    _registry: ff.Registry = None
    _decode_token: DecodeToken = None

    def __call__(self, **kwargs):
        pass

    @staticmethod
    def _make_response(data: Union[dict, ff.Envelope] = None, headers: dict = None, forwarding_address: str = None, cookies: List[dict] = None):
        if isinstance(data, ff.Envelope):
            message = data
        else:
            message = {'message': 'success'}
            if data:
                message['data'] = data
            message = ff.Envelope.wrap(message)
        if headers:
            message = message.set_raw_request(headers)
        if forwarding_address:
            message = message.add_forwarding_address(forwarding_address)
        # if cookies:
        #     message = message.set_cookies(cookies)
        return message

    @staticmethod
    def _make_error_response(error: Union[str, dict]):
        resp = {'message': 'error'}
        resp['error'] = error if isinstance(error, str) else error['error']
        return ff.Envelope.wrap(resp)
