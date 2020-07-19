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

from firefly.ui.web.polyfills import *  # __:skip
from firefly.ui.web.js_libs.mithril import m
from firefly.ui.web import bus, Form
from firefly_iaaa_web.state import state

from firefly_iaaa.domain.entity.user import User


# __pragma__('opov')
class UserForm:
    def __init__(self):
        self.form = Form(
            User(),
            {
                'onsubmit': lambda data: bus.invoke('iam.CreateUser', User(**data).to_dict()),
                'fieldsets': [
                    {
                        'fields': ['given_name', 'middle_name', 'family_name', 'name', 'nickname', 'gender', 'birthdate'],
                        'legend': 'Personal',
                    },
                    {
                        'fields': ['email', 'email_verified', 'phone_number', 'phone_number_verified'],
                        'legend': 'Contact',
                    },
                    {
                        'fields': ['address'],
                        'legend': 'Address',
                    },
                    {
                        'fields': ['preferred_username', 'locale', 'picture', 'profile', 'website', 'zoneinfo'],
                        'legend': 'Account',
                    }
                ]
            }
        )

    def view(self):
        return [
            m('h1', 'User Form'),
            m(self.form),
            m('h1', 'Users'),
            m('ul', map(lambda u: m('li', u.given_name), state.users()))
        ]
# __pragma__('noopov')
