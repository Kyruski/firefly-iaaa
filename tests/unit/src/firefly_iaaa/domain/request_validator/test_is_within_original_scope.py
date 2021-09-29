import pytest


def test_is_within_original_scope(validator, oauth_request_list):
    assert validator.is_within_original_scope()
    assert False
