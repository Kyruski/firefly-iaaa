from __future__ import annotations

import firefly as ff
import firefly_iaaa.domain as domain


@ff.command_handler()
class RemoveRoleFromUser(ff.ApplicationService):
    _registry: ff.Registry = None

    def __call__(self, sub: str, role_id: str = None, role_name: str = None, **kwargs):
        if role_id is None and role_name is None:
            raise ff.ApiError('must provide one of role_id or role_name')

        if role_id is not None:
            role = self._registry(domain.Role).find(role_id)
        else:
            role = self._registry(domain.Role).find(lambda r: r.name == role_name)

        if not role:
            raise ff.NotFound('role not found')

        user = self._registry(domain.User).find(lambda x: (x.sub == sub) & (x.deleted_at.is_none()))
        if not user:
            raise ff.NotFound('user not found')

        user.roles.remove(role)
