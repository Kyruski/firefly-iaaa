from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator



def test_get_default_redirect_uri(validator: OauthlibRequestValidator, oauth_request_list: List[Request]):
    for i in range(6):
        assert validator.get_default_redirect_uri('', oauth_request_list[i]) == f'https://www.uri{i}.com'
