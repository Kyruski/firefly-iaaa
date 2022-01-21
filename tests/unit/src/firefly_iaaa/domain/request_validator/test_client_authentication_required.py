from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.user import User


from firefly_iaaa.domain.service.request_validator import OauthRequestValidators


def test_client_authentication_required(validator: OauthRequestValidators, oauth_request_list: List[Request], user_list: List[User]):

    # Check request with no headers should return False
    assert validator.client_authentication_required(oauth_request_list[-1]) == False, "Testing with no headers or client_id, should return False"

    # Check request with correct headers/login returns Trye
    oauth_request_list[-1].body['username'] = user_list[0]
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.client_authentication_required(oauth_request_list[-1]) == True, "Testing with headers but no client_id, should return True"

    # Check missing headers returns False (Clearing headers)
    oauth_request_list[-1].body['username'] = None
    oauth_request_list[-1].body['password'] = None
    assert validator.client_authentication_required(oauth_request_list[-1]) == False, "Clearing headers, should return False"
    # Check mismatching username/password still returns true (only checking headers exists)
    oauth_request_list[-1].body['username'] = user_list[1]
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.client_authentication_required(oauth_request_list[-1]) == True #Doesn't matter if password wrong, it should still return true if headers exist

    for i in range(7):
        # Checking if authentication required for client
        # Based off grant type/is confidential client
        oauth_request_list[i].client_id = oauth_request_list[i].client.client_id
        assert validator.client_authentication_required(oauth_request_list[i]) == (i in (2, 3, 4, 6))

    # Check missing client_id returns False
    oauth_request_list[3].client_id = None
    assert validator.client_authentication_required(oauth_request_list[3]) == False
