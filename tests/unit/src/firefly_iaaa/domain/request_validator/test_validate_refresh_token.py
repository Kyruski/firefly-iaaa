import pytest


def test_validate_refresh_token(validator, oauth_request_list, bearer_tokens_list, registry):
    for i in range(4):
        for x in range(3):
            bearer_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
            bearer_token = bearer_tokens_list[i][bearer_selector]
            assert oauth_request_list[i].user is None
            assert validator.validate_refresh_token(bearer_token.refresh_token, oauth_request_list[i].client, oauth_request_list[i]) == (x == 0)
            assert (oauth_request_list[i].user == bearer_token.user) == (x == 0)
            oauth_request_list[i].user = None
            assert oauth_request_list[i].user is None
            assert validator.validate_refresh_token(bearer_token.refresh_token, oauth_request_list[(i + 1) % 4].client, oauth_request_list[i]) == False #Check for wrong client
            assert oauth_request_list[i].user is None
