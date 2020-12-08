from __future__ import annotations

import firefly as ff


class Tenant(ff.AggregateRoot):
    id: str = ff.id_()
    name: str = ff.required()
