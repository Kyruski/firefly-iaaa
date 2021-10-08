from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.user import User


from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidators


def test_client_authentication_required(validator: OauthlibRequestValidators, oauth_request_list: List[Request], user_list: List[User]):
    assert validator.client_authentication_required(oauth_request_list[-1]) == False, "Testing with no headers or client_id, should return False"
    oauth_request_list[-1].body['username'] = user_list[0]
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.client_authentication_required(oauth_request_list[-1]) == True, "Testing with headers but no client_id, should return True"
    oauth_request_list[-1].body['username'] = None
    oauth_request_list[-1].body['password'] = None
    assert validator.client_authentication_required(oauth_request_list[-1]) == False, "Clearing headers, should return False"
    oauth_request_list[-1].body['username'] = user_list[1]
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.client_authentication_required(oauth_request_list[-1]) == True #Doesn't matter if password wrong, it should still return true if headers exist

    oauth_request_list[0].client_id = oauth_request_list[0].client.client_id
    oauth_request_list[1].client_id = oauth_request_list[1].client.client_id
    oauth_request_list[2].client_id = oauth_request_list[2].client.client_id
    oauth_request_list[3].client_id = oauth_request_list[3].client.client_id
    oauth_request_list[4].client_id = oauth_request_list[4].client.client_id
    oauth_request_list[5].client_id = oauth_request_list[5].client.client_id
    oauth_request_list[6].client_id = oauth_request_list[6].client.client_id
    assert validator.client_authentication_required(oauth_request_list[0]) == False
    assert validator.client_authentication_required(oauth_request_list[1]) == False
    assert validator.client_authentication_required(oauth_request_list[2]) == True
    assert validator.client_authentication_required(oauth_request_list[3]) == True
    assert validator.client_authentication_required(oauth_request_list[4]) == True
    assert validator.client_authentication_required(oauth_request_list[5]) == False
    assert validator.client_authentication_required(oauth_request_list[6]) == True
    oauth_request_list[3].client_id = None
    assert validator.client_authentication_required(oauth_request_list[3]) == False
