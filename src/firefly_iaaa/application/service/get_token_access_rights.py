from __future__ import annotations

import firefly as ff


@ff.query_handler()
class GetTokenAccessRights(ff.ApplicationService):
    _repository: ff.Repository = None

    def __call__(self, event: dict, **kwargs):
        print(event)
        return event
