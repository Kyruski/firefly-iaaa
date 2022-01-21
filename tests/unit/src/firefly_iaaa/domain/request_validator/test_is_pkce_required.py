from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.client import Client

from firefly_iaaa.domain.service.request_validator import OauthRequestValidators

def test_is_pkce_required(validator: OauthRequestValidators, oauth_request_list: List[Request], client_list: List[Client]):
    for i in range(4):
        # Check pkce is require (fixture has pkce required on i % 2 == 0)
        assert validator.is_pkce_required('', oauth_request_list[i]) == (i % 2 == 0)
