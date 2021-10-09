from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidators



def test_authenticate_client_id(validator: OauthlibRequestValidators, oauth_request_list: List[Request]):
    for i in range(5):
        # Check returns True when client_id supplied on request with no client_id parameter (i == 0 or 1 is False because they are confidential clients and need authentication)
        oauth_request_list[i].client_id = oauth_request_list[i].client.client_id
        assert validator.authenticate_client_id('', oauth_request_list[i]) == (i >= 2) #Seems like arbitrary decission, but clients at index 0 and 1 are False, rest are True
    
    # Check returns False when no client_id in parameter or request
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == False 
    # Check returns False when client_id belongs to confidential client
    assert validator.authenticate_client_id(oauth_request_list[1].client.client_id, oauth_request_list[-1]) == False 

    # Check returns True when no client object on request but non-confidential client_id provided
    oauth_request_list[-1].client = None
    assert validator.authenticate_client_id(oauth_request_list[2].client.client_id, oauth_request_list[-1]) == True 
    # Check valid because cleint set on request object from previous assert
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == True 
