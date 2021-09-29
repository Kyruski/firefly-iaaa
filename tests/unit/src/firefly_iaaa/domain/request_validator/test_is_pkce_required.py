import pytest


def test_is_pkce_required(validator, oauth_request_list, client_list):
    for i in range(4):
        assert validator.is_pkce_required('', oauth_request_list[i]) == (i % 2 == 0)
