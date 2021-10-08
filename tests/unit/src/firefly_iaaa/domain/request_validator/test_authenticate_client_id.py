from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidators



def test_authenticate_client_id(validator: OauthlibRequestValidators, oauth_request_list: List[Request]):
    for i in range(5):
        oauth_request_list[i].client_id = oauth_request_list[i].client.client_id
        assert validator.authenticate_client_id('', oauth_request_list[i]) == (i >= 2) #Seems like arbitrary decission, but clients at index 0 and 1 are False, rest are True
    
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == False 
    assert validator.authenticate_client_id(oauth_request_list[1].client.client_id, oauth_request_list[-1]) == False 
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == False 
    oauth_request_list[-1].client = None
    assert validator.authenticate_client_id(oauth_request_list[2].client.client_id, oauth_request_list[-1]) == True 
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == True 
