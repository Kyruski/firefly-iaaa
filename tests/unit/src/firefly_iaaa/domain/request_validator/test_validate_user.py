
import pytest


def test_validate_user(validator, oauth_request_list, user_list):

    for i in range(4):
        assert oauth_request_list[i].user is None
        assert validator.validate_user(user_list[i].email, f'password{i + 1}', oauth_request_list[i].client, oauth_request_list[i]) == True
        assert oauth_request_list[i].user == user_list[i]
        oauth_request_list[i].user = None
        assert oauth_request_list[i].user is None
        assert validator.validate_user(user_list[i].email, f'password{i}', oauth_request_list[i].client, oauth_request_list[i]) == False
        assert oauth_request_list[i].user is None
        assert validator.validate_user(f'user{i}@fake.com', f'password{i + 1}', oauth_request_list[i].client, oauth_request_list[i]) == False
        assert oauth_request_list[i].user is None
