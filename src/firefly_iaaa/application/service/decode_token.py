from __future__ import annotations

import firefly as ff
from jwt import ExpiredSignatureError

from firefly_iaaa import domain


@ff.query_handler()
class DecodedToken(ff.ApplicationService):
    _decode_token: domain.DecodeToken = None

    def __call__(self, token: str, audience: str = None, **kwargs):
        try:
            return self._decode_token(token, audience)
        except ExpiredSignatureError:
            return {'message': 'error', 'error': 'Expired Token'}
