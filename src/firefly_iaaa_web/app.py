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

from firefly.ui.web.components.layouts.default import compose, default_layout
from firefly.ui.web.js_libs.mithril import m
from firefly.ui.web.polyfills import *  # __:skip

# from firefly_iaaa_web.components.clients_page import ClientsPage
# from firefly_iaaa_web.components.main_menu import MainMenu

m.route.prefix = ''


def counter():
    count = 0

    def increment():
        nonlocal count
        count += 1
        console.log(count)

    def decrement():
        nonlocal count
        count -= 1

    return {
        'view': lambda vnode: m('div', [
            m('p', f'count: {count}'),
            m('button', {'onclick': increment}, 'Increment'),
            m('button', {'onclick': decrement}, 'Decrement'),
        ])
    }


def main_content():
    return {
        'view': lambda: m('div.flex.flex-col', [
            m(counter),
            m(counter),
        ])
    }


def custom_header():
    return {
        'view': lambda: m('div', 'bleck')
    }


m.route(document.body, '/', {
    '/': compose(default_layout, main_content),
})

"""
__pragma__('js', '{}', '''
if (module.hot) {
  module.hot.accept();
}
''')
"""

