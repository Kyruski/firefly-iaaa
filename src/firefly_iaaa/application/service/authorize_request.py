from __future__ import annotations

import firefly as ff

from firefly_iaaa import domain

@ff.query_handler()
class AuthorizeRequest(ff.ApplicationService):
    _authorize_request: domain.AuthorizeRequest = None

    def __call__(self, **kwargs):
        return self._authorize_request(**kwargs)
