from __future__ import annotations

import firefly as ff

from firefly_iaaa import domain


@ff.query_handler()
class DecodedToken(ff.ApplicationService):
    _decode_token: domain.DecodeToken = None

    def __call__(self, token: str, audience: str = None, **kwargs):
        return self._decode_token(token, audience)
