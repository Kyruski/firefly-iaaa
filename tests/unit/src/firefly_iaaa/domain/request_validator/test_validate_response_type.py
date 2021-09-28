
import pytest


def test_validate_response_type(validator, oauth_request_list):
    allowed_response_types = [['code'], ['token'], ['code', 'token'], ['token', 'code']]
    for i in range(4):
        assert validator.validate_response_type('', 'code', oauth_request_list[i].client, oauth_request_list[i]) == ('code' in allowed_response_types[i])
        assert validator.validate_response_type('', 'token', oauth_request_list[i].client, oauth_request_list[i]) == ('token' in allowed_response_types[i])
        assert validator.validate_response_type('', 'id_token', oauth_request_list[i].client, oauth_request_list[i]) == False

