from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.user import User

from firefly_iaaa.domain.service.request_validator import OauthRequestValidators



def test_authenticate_client(validator: OauthRequestValidators, oauth_request_list: List[Request], user_list: List[User]):

    # Check not valid when no headers or client_id
    assert validator.authenticate_client(oauth_request_list[-1]) == False, "Testing with no headers or client_id, should return False"

    # Check validates when correct username-password combo given
    oauth_request_list[-1].body['username'] = user_list[0].email
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.authenticate_client(oauth_request_list[-1]) == True, "Testing with headers but no client_id, should return True"

    # Reset headers to none, check fails
    oauth_request_list[-1].body['username'] = None
    oauth_request_list[-1].body['password'] = None
    assert validator.authenticate_client(oauth_request_list[-1]) == False, "Clearing headers, should return False"

    # Check incorrect username-password combo returns False
    oauth_request_list[-1].body['username'] = user_list[1].email
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.authenticate_client(oauth_request_list[-1]) == False

    # Adding client_id to request
    for i in range(5):
        # Check matching client_id and client_secret returns True
        oauth_request_list[-1].client_id = oauth_request_list[i].client.client_id
        oauth_request_list[-1].body['client_secret'] = oauth_request_list[i].client.client_secret
        assert validator.authenticate_client(oauth_request_list[-1]) == True

        # Check mismatching/invalid client_id and client_secret returns False
        oauth_request_list[i].client_id = oauth_request_list[i].client.client_id
        oauth_request_list[i].body['client_secret'] = 'oauth_request_list[i].client.client_secret'
        assert validator.authenticate_client(oauth_request_list[i]) == False
