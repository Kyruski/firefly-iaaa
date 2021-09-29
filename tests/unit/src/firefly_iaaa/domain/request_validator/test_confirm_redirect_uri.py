import pytest


def test_confirm_redirect_uri(validator, oauth_request_list, client_list):
    for i in range(4):
        assert validator.confirm_redirect_uri()
    assert False
