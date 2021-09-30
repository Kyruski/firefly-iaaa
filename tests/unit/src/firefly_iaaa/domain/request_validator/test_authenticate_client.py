from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.user import User

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator



def test_authenticate_client(validator: OauthlibRequestValidator, oauth_request_list: List[Request], user_list: List[User]):
    assert validator.authenticate_client(oauth_request_list[-1]) == False, "Testing with no headers or client_id, should return False"
    oauth_request_list[-1].body['username'] = user_list[0].email
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.authenticate_client(oauth_request_list[-1]) == True, "Testing with headers but no client_id, should return True"
    oauth_request_list[-1].body['username'] = None
    oauth_request_list[-1].body['password'] = None
    assert validator.authenticate_client(oauth_request_list[-1]) == False, "Clearing headers, should return False"
    oauth_request_list[-1].body['username'] = user_list[1].email
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.authenticate_client(oauth_request_list[-1]) == False #Doesn't matter if password wrong, it should still return true if headers exist

    for i in range(5):
        oauth_request_list[-1].client_id = oauth_request_list[i].client.client_id
        oauth_request_list[-1].body['client_secret'] = oauth_request_list[i].client.client_secret
        assert validator.authenticate_client(oauth_request_list[-1]) == True
        oauth_request_list[i].client_id = oauth_request_list[i].client.client_id
        oauth_request_list[i].body['client_secret'] = 'oauth_request_list[i].client.client_secret'
        assert validator.authenticate_client(oauth_request_list[i]) == False
