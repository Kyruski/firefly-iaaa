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

from firefly.ui.web.components.firefly_logo import FireflyLogo, FireflyIcon
from firefly.ui.web.polyfills import *  # __:skip
from firefly.ui.web.js_libs.mithril import m


class MainMenu:
    PAGES = ('clients', 'users')

    def __init__(self, exclude: List[str] = None):
        self._exclude = exclude or []

    def _menu_item(self, page: str):
        if page in self._exclude:
            return None

        return m(
            'div.pl-3.py-1',
            m(m.route.Link, {'href': f'/{page}'}, page)
        )

    def view(self):
        return m(
            'div.flex.flex-col.justify-start', [
                m(FireflyLogo()),
                list(map(self._menu_item, self.PAGES))
            ]
        )
