import pytest


def test_get_default_redirect_uri(validator, oauth_request_list, client_list):
    for i in range(4):
        assert validator.get_default_redirect_uri('', oauth_request_list[i]) == f'www.uri{i}.com'
