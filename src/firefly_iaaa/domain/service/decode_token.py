from __future__ import annotations

import firefly as ff
import jwt


class DecodeToken(ff.DomainService):
    _secret_key: str = None

    def __call__(self, token: str, audience: str = None, **kwargs):
        if token.lower().startswith('bearer'):
            token = token.split(' ')[-1]
        if not audience:
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                audience = decoded['aud']
            except KeyError:
                return False
        return jwt.decode(token, self._secret_key, 'HS256', audience=audience)
