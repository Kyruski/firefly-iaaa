from __future__ import annotations
from typing import List

from oauthlib.common import Request
from firefly_iaaa.domain.entity.user import User
from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator


def test_validate_user(validator: OauthlibRequestValidator, oauth_request_list: List[Request], user_list: List[User]):

    for i in range(6):
        assert oauth_request_list[i].user is None
        assert validator.validate_user(user_list[i].email, f'password{i + 1}', oauth_request_list[i].client, oauth_request_list[i]) == True
        assert oauth_request_list[i].user == user_list[i]
        oauth_request_list[i].user = None
        assert oauth_request_list[i].user is None
        assert validator.validate_user(user_list[i].email, f'password{i}', oauth_request_list[i].client, oauth_request_list[i]) == False
        assert oauth_request_list[i].user is None
        assert validator.validate_user(f'nouser{i}@fake.com', f'password{i + 1}', oauth_request_list[i].client, oauth_request_list[i]) == False
        assert oauth_request_list[i].user is None
