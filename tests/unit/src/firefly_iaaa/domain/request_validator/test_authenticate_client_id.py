import pytest


def test_authenticate_client_id(validator, oauth_request_list):
    for i in range(5):
        oauth_request_list[i].client_id = oauth_request_list[i].client.client_id
        assert validator.authenticate_client_id('', oauth_request_list[i]) == (i >= 2) #Seems like arbitrary decission, but clients at index 0 and 1 are False, rest are True
    
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == False 
    assert validator.authenticate_client_id(oauth_request_list[1].client.client_id, oauth_request_list[-1]) == False 
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == False 
    oauth_request_list[-1].client = None
    assert validator.authenticate_client_id(oauth_request_list[2].client.client_id, oauth_request_list[-1]) == True 
    assert validator.authenticate_client_id('', oauth_request_list[-1]) == True 
