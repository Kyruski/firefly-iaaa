
import pytest


def test_validate_redirect_uri(validator, oauth_request_list):
    for i in range(4):
        assert validator.validate_redirect_uri('', f'www.uri{i}.com', oauth_request_list[i]) == True
        assert validator.validate_redirect_uri('', f'www.uri{i + 1}.com', oauth_request_list[i]) == False
        assert validator.validate_redirect_uri('', f'www.fake.com', oauth_request_list[i]) == True
