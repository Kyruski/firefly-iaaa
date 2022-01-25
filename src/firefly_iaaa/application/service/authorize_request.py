from __future__ import annotations

import firefly as ff

from firefly_iaaa import domain

@ff.query_handler()
class AuthorizeRequest(ff.ApplicationService):
    _authorize_request: domain.AuthorizeRequest = None

    def __call__(self, token: str, **kwargs):
        kwargs['access_token'] = token
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers']['uri'] = ''
        return self._authorize_request(**kwargs)
