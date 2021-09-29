import pytest


def test_authenticate_client(validator, oauth_request_list):
    assert validator.authenticate_client(oauth_request_list[-1]) == False, "Testing with no headers or client_id, should return False"
    oauth_request_list[-1].body['username'] = 'user1@fake.com'
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.authenticate_client(oauth_request_list[-1]) == True, "Testing with headers but no client_id, should return True"
    oauth_request_list[-1].body['username'] = None
    oauth_request_list[-1].body['password'] = None
    assert validator.authenticate_client(oauth_request_list[-1]) == False, "Clearing headers, should return False"
    oauth_request_list[-1].body['username'] = 'user2@fake.com'
    oauth_request_list[-1].body['password'] = 'password1'
    assert validator.authenticate_client(oauth_request_list[-1]) == False #Doesn't matter if password wrong, it should still return true if headers exist

    oauth_request_list[0].client_id = oauth_request_list[0].client.client_id
    oauth_request_list[1].client_id = oauth_request_list[1].client.client_id
    oauth_request_list[2].client_id = oauth_request_list[2].client.client_id
    oauth_request_list[3].client_id = oauth_request_list[3].client.client_id
    oauth_request_list[4].client_id = oauth_request_list[4].client.client_id
    assert validator.authenticate_client(oauth_request_list[0]) == False
    assert validator.authenticate_client(oauth_request_list[1]) == False
    assert validator.authenticate_client(oauth_request_list[2]) == True
    assert validator.authenticate_client(oauth_request_list[3]) == True
    assert validator.authenticate_client(oauth_request_list[4]) == True
    assert False
