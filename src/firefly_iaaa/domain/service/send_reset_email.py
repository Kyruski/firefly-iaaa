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


class SendResetEmail(ff.DomainService):
    _subdomain: str = None
    _reset_url: str = None
    _from_address: str = None

    def __call__(self, username: str, cache_id: str, **kwargs):
        reset_url = f'{self._reset_url}?request_id={cache_id}'
        html_body = self._gen_html_body(reset_url)
        text_body = self._gen_text_body(reset_url)

        data = {
            'subject': 'PWR Lab Password Reset',
            'text_body': text_body,
            'html_body': html_body,
            'from_address': self._from_address,
            'to_address': [username],
            'cc_addresses': [],
            'bcc_addresses': []
        }
        try:
            x = self.invoke('messaging.SendSESEmail', data)
            return True
        except Exception as e:
            return False

    def _gen_html_body(self, reset_url):
        return f"""<h1 style="text-align: center;">Password Reset</h1>
<br><br>
Trouble signing in? We received a request to reset your password.
<br><br>
If you would like to continue with resetting the password for your account, <a href="{reset_url}" >Click Here</a>. Or copy and paste this URL into your browser: <br><a href="{reset_url}" >{reset_url}</a>
<br><br>
If you did not request this password reset, please ignore this message.
<br><br>
Cheers,
<br>
-PwrLab Team
"""

    def _gen_text_body(self, reset_url):
        return f"""Password Reset

Trouble signing in? We received a request to reset your password.

If you would like to continue with resetting the password for your account, copy and paste this URL into your browser: {reset_url}

If you did not request this password reset, please ignore this message.

Cheers,
-PwrLab Team
"""
