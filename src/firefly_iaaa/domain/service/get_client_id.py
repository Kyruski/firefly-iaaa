from __future__ import annotations

import firefly as ff
import firefly_iaaa.domain as domain


class GetClientId(ff.DomainService):
    _kernel: ff.Kernel = None
    _registry: ff.Registry = None

    def __call__(self, client_id: str, **kwargs):
        if client_id:
            return client_id
        user = self._registry(domain.User).find(lambda x: (x.sub == self._kernel.user.id) & (x.deleted_at.is_none()))
        if not user:
            return self._kernel.user.id
        client = self._registry(domain.Client).find(lambda x: x.tenant_id == user.tenant_id)
        if client is None:
            client = self._registry(domain.Client).find(lambda x: x.client_id == user.sub)
        return client.client_id