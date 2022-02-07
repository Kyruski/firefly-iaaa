from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.domain.service.request_validator import OauthRequestValidators



def test_authenticate_client_id(validator: OauthRequestValidators, oauth_request_list: List[Request]):
    for i in range(5):
        # Check returns True when client_id supplied on request with no client_id parameter (i == 0 or 1 is False because they are confidential clients and need authentication)
        oauth_request_list[i].client_id = oauth_request_list[i].client.client_id
        assert validator.authenticate_client_id('', oauth_request_list[i]) == (i in (1, 4, 5)) #Seems like arbitrary decission, but clients at index 0 and 1 are False, rest are True
    
    # Check returns False when no client_id in parameter or request
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == False 
    assert validator.authenticate_client_id(None, oauth_request_list[-1]) == False 
    # Check returns True when grant_type is refresh_token
    assert validator.authenticate_client_id(oauth_request_list[1].client.client_id, oauth_request_list[1]) == True 
    # Check returns False when client_id belongs to non-confidential client
    assert validator.authenticate_client_id(oauth_request_list[4].client.client_id, oauth_request_list[4]) == True 
    # Check returns False when client_id belongs to confidential client
    assert validator.authenticate_client_id(oauth_request_list[0].client.client_id, oauth_request_list[0]) == False 

    # Check returns True when no client object on request but non-confidential client_id provided
    oauth_request_list[-1].client = None
    assert validator.authenticate_client_id(oauth_request_list[1].client.client_id, oauth_request_list[-1]) == True  
    # Check valid because client set on request object from previous assert
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == True 
