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

import importlib
import os

from botocore.exceptions import ClientError

import firefly as ff
import firefly_iaaa.domain as domain


class OAuthRegister(ff.DomainService):
    _oauth_login: domain.OAuthLogin = None
    _registry: ff.Registry = None
    _make_user: domain.MakeClientUserEntities = None
    _context_map: ff.ContextMap = None
    _context: str = None
    _user_created_event = os.environ.get('USER_CREATED_EVENT') or 'iaaa.UserCreated'

    def __call__(self, passed_in_kwargs: dict):
        self.info('Registering User')
        username = passed_in_kwargs['username']

        module_name = self._context_map.\
            get_context(self._context).\
            config.\
            get('domain_module', '{}.domain')
        module = importlib.import_module(module_name.format(self._context))
        user_entity = module.__dict__.get('User')

        try:
            found_user = self._registry(user_entity).find(lambda x: x.email.lower() == username)
        except ClientError as e:
            if e.response['Error']['Code'] == 'BadRequestException':
                if 'syntax error at or near ")"' in str(e):
                    return {'message': 'error', 'error': 'User already exists'}
            raise e
        if found_user:
            return {'message': 'error','error': 'User already exists'}

        passed_in_kwargs.update({
            'tenant_name': f'user_tenant_{username}',
            'grant_type': 'password',
            'scopes': []
        })

        user = self._make_user(**passed_in_kwargs)
        self.dispatch(self._user_created_event, data=user.to_dict())

        return True
