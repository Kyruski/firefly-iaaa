import pytest


def test_validate_client_id(validator, oauth_request_list):
    assert oauth_request_list[-1].client is None
    assert validator.validate_client_id('', oauth_request_list[-1]) == False
    assert oauth_request_list[-1].client is None
    oauth_request_list[-1].client = None

    assert oauth_request_list[-1].client is None
    assert validator.validate_client_id('000000', oauth_request_list[-1]) == False
    assert oauth_request_list[-1].client is None
    oauth_request_list[-1].client = None

    assert oauth_request_list[-1].client is None
    assert validator.validate_client_id(oauth_request_list[0].client.client_id, oauth_request_list[-1]) == True
    assert oauth_request_list[-1].client is not None
    oauth_request_list[-1].client = None

    assert oauth_request_list[1].client is not None
    assert validator.validate_client_id(oauth_request_list[0].client.client_id, oauth_request_list[1]) == True
    assert oauth_request_list[1].client.client_id != oauth_request_list[0].client.client_id
