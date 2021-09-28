
import pytest


def test_validate_user(validator, oauth_request_list, user_list):
    # print(user_list)
    for i in range(4):
        assert validator.validate_user(f'user{i + 1}@fake.com', f'password{i + 1}', oauth_request_list[i].client, oauth_request_with_client[i])
