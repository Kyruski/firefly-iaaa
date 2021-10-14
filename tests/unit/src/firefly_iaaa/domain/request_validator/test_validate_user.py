from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.user import User
from firefly_iaaa.infrastructure.service.request_validator import OauthRequestValidators


def test_validate_user(validator: OauthRequestValidators, oauth_request_list: List[Request], user_list: List[User]):

    for i in range(6):
        # Checking if it logs in correctly
        assert oauth_request_list[i].user is None
        assert validator.validate_user(user_list[i].email, f'password{i + 1}', oauth_request_list[i].client, oauth_request_list[i]) == True
        assert oauth_request_list[i].user == user_list[i]

        # Reseting user on the Request
        oauth_request_list[i].user = None
        assert oauth_request_list[i].user is None

        # Should not validate with wrong password
        assert validator.validate_user(user_list[i].email, f'password{i}', oauth_request_list[i].client, oauth_request_list[i]) == False
        assert oauth_request_list[i].user is None

        # Should not validate with wrong username
        assert validator.validate_user(f'notuser{i}@fake.com', f'password{i + 1}', oauth_request_list[i].client, oauth_request_list[i]) == False
        assert oauth_request_list[i].user is None
