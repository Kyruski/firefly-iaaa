from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.infrastructure.service.request_validator import OauthRequestValidators


def test_validate_client_id(validator: OauthRequestValidators, oauth_request_list: List[Request]):

    # Check wrong/missing client_id does not validate
    assert oauth_request_list[-1].client is None
    assert validator.validate_client_id('', oauth_request_list[-1]) == False
    assert oauth_request_list[-1].client is None

    # Check wrong client_id does not validate
    assert validator.validate_client_id('000000', oauth_request_list[-1]) == False
    assert oauth_request_list[-1].client is None

    # Check correct client_id does validate when request does not have request.client
    assert validator.validate_client_id(oauth_request_list[0].client.client_id, oauth_request_list[-1]) == True
    assert oauth_request_list[-1].client is not None

    # Check correct client_id does validate when request does include request.client (and client_id not empty)
    assert oauth_request_list[1].client is not None
    assert validator.validate_client_id(oauth_request_list[0].client.client_id, oauth_request_list[1]) == True
    assert oauth_request_list[1].client.client_id != oauth_request_list[0].client.client_id

    # Check correct client_id does validate when request does include request.client (and client_id is empty)
    assert oauth_request_list[3].client is not None
    assert validator.validate_client_id('', oauth_request_list[3]) == True
    assert oauth_request_list[3].client.client_id != oauth_request_list[0].client.client_id