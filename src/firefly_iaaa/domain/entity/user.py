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

from datetime import datetime, date
from typing import List

import bcrypt
import firefly as ff

from firefly_iaaa.domain.entity.role import Role
from firefly_iaaa.domain.entity.tenant import Tenant
from firefly_iaaa.domain.value_object.address import Address


class User(ff.AggregateRoot):
    # OpenID standard fields
    sub: str = ff.id_(validators=[ff.HasLength(36)])
    name: str = ff.optional()
    given_name: str = ff.optional()
    family_name: str = ff.optional()
    middle_name: str = ff.optional()
    nickname: str = ff.optional()
    preferred_username: str = ff.optional(index=True)
    profile: str = ff.optional()
    picture: str = ff.optional()
    website: str = ff.optional()
    email: str = ff.optional(validators=[ff.IsValidEmail()], index=True, unique=True)
    email_verified: bool = ff.optional(default=False)
    gender: str = ff.optional(validators=[ff.IsOneOf(('Male', 'Female'))])
    birthdate: date = ff.optional()
    zoneinfo: str = ff.optional()
    locale: str = ff.optional()
    phone_number: str = ff.optional()
    phone_number_verified: bool = ff.optional(default=False)
    address: Address = ff.optional()
    updated_at: datetime = ff.now()

    # Custom fields
    created_at: datetime = ff.now(internal=True)
    deleted_at: datetime = ff.optional(index=True, internal=True)
    password_hash: str = ff.optional(length=32, internal=True)
    salt: str = ff.optional(internal=True)
    roles: List[Role] = ff.list_(internal=True)
    tenant: Tenant = ff.optional(index=True, internal=True)
    tenant_id: str = ff.optional(index=True, internal=True)

    @classmethod
    def create(cls, **kwargs):
        if 'email' in kwargs:
            kwargs['email'] = str(kwargs['email']).lower()
        if kwargs.get('password'):
            kwargs['salt'] = bcrypt.gensalt().decode()
            kwargs['password_hash'] = User._hash_password(kwargs['password'], kwargs['salt'])
        try:
            kwargs['tenant_id'] = kwargs['tenant'].id
        except KeyError:
            raise ff.MissingArgument('Tenant is a required field for User::create()')

        return cls(**ff.build_argument_list(kwargs, cls))

    @classmethod
    def _hash_password(cls, password: str, salt: str):
        return bcrypt.hashpw(password.encode('utf-8'), salt.encode()).decode('utf-8')

    def change_password(self, new_password: str):
        if self.salt is None:
            self.salt = bcrypt.gensalt().decode()
        self.password_hash = self._hash_password(new_password, self.salt)

    def change_email(self, new_email: str):
        self.email = new_email

    def add_role(self, role: Role):
        if isinstance(role, Role):
            self.roles.append(role)
    
    def remove_role(self, role: Role):
        if isinstance(role, Role):
            self.roles.remove(role)

    def correct_password(self, password: str):
        if not password or not self.password_hash:
            return False
        return self.password_hash == User._hash_password(password, self.salt)

    def generate_scrubbed_user(self):
        resp = {
            'sub': self.sub,
            'name': self.name,
            'given_name': self.given_name,
            'family_name': self.family_name,
            'middle_name': self.middle_name,
            'nickname': self.nickname,
            'preferred_username': self.preferred_username,
            'profile': self.profile,
            'picture': self.picture,
            'website': self.website,
            'email': self.email,
            'email_verified': self.email_verified,
            'gender': self.gender,
            'birthdate': self.birthdate,
            'zoneinfo': self.zoneinfo,
            'locale': self.locale,
            'phone_number': self.phone_number,
            'phone_number_verified': self.phone_number_verified,
            'updated_at': self.updated_at,
            'created_at': self.created_at,
        }
        if self.tenant is not None:
            resp['tenant_id'] = self.tenant.id,
        return resp

    def get_scopes(self):
        return [scope.id for role in self.roles for scope in role.scopes]
