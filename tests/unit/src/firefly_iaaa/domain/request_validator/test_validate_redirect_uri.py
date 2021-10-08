from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidators


def test_validate_redirect_uri(validator: OauthlibRequestValidators, oauth_request_list: List[Request]):
    for i in range(6):
        assert validator.validate_redirect_uri('', f'https://www.uri{i}.com', oauth_request_list[i]) == True
        assert validator.validate_redirect_uri('', f'https://www.uri{i + 1}.com', oauth_request_list[i]) == False
        assert validator.validate_redirect_uri('', f'https://www.fake.com', oauth_request_list[i]) == True
