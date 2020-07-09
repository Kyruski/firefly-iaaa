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
from firefly.ui.web.js_libs.mithril import m, Stream

from typing import Any, Callable

from firefly import Query, MessageFactory, Message
from firefly.ui.web.bus import bus


def __pragma__(*args):
    pass

# __pragma__('js', '{}', "var inflection = require('inflection');")

# __pragma__('opov')
# __pragma__('kwargs')

import iam

mf = MessageFactory()


class QueryStream:
    _bus = bus

    def __init__(self, query: Query = None, default: Any = None, fetch: str = 'lazy', handlers: dict = None,
                 refresh_on: list = None):
        self._initialized = False
        self._query = query
        self._stream = Stream(default or [])
        self._stream.map(lambda: m.redraw())

        def _set_stale(val):
            self._stale = False
        self._stream.map(_set_stale)

        self._aggregate = inflection.singularize(query.__class__.__name__)
        self._stale = False

        if handlers is not None:
            for command, handler in handlers.items():
                def mw(message: Message, next_: Callable):
                    context, cmd = str(command).split('.')
                    if message.get_context() == context and message.__class__.__name__ == cmd:
                        self._stream(handler(message, self._stream()))
                    return next_(message)
                self._bus.insert_command_handler(1, mw)

        if refresh_on is not None:
            for command in refresh_on:
                def mw(message: Message, next_: Callable):
                    context, cmd = str(command).split('.')
                    ret = next_(message)
                    if message.get_context() == context and message.__class__.__name__ == cmd:
                        if hasattr(ret, 'then'):
                            return ret.then(lambda _: self.refresh())
                    return ret
                self._bus.insert_command_handler(1, mw)

        if fetch == 'eager':
            self._execute_query()

    def __call__(self, value: Callable = None):
        if value is None:
            if not self._initialized:
                self._execute_query()
            return self._stream()
        return self._stream(value)

    def __getattr__(self, item):
        return getattr(self._stream, item)

    def matches_aggregate(self, aggregate: str):
        return self._aggregate == aggregate

    def refresh(self):
        self._execute_query()

    def is_stale(self):
        return self._stale

    def _execute_query(self):
        self._stale = True
        self._bus.request(self._query).then(self._stream)
        self._initialized = True


class State:
    def __init__(self):
        self.users = QueryStream(
            query=mf.query('iam.Users'),
            default=[],
            handlers={
                'iam.CreateUser': lambda c, s: s + [iam.User(**c.to_dict())]
            },
        )


state = State()
