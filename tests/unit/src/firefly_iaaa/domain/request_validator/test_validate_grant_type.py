import pytest


def test_validate_grant_type(validator, oauth_request_list):
    grant_types = ['Authorization Code', 'Implicit', 'Resource Owner Password Credentials', 'Client Credentials']
    for i in range(4):
        for x in range(4):
            assert validator.validate_grant_type('', grant_types[x], oauth_request_list[i].client, oauth_request_list[i]) == (i == x)
            assert validator.validate_grant_type('', grant_types[(x + 1) % 4], oauth_request_list[i].client, oauth_request_list[i]) == (i == (x + 1) % 4)
