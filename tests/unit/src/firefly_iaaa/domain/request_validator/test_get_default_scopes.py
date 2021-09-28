import pytest


def test_get_default_scopes(validator, oauth_request_list):
    for i in range(4):
        assert validator.get_default_scopes('', oauth_request_list[i]) == ['fake scopes', f'faker scope{i}'], 'Tests client existing on request'

