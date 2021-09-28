import pytest


def test_validate_scopes(validator, oauth_request_list):
    scopes = ['fake scopes', 'faker scope']
    for i in range(4):
        assert validator.validate_scopes('', [scopes[0], f'{scopes[1]}{i}'], oauth_request_list[i].client, oauth_request_list[i]) == True
        assert validator.validate_scopes('', [*scopes, 'abc'], oauth_request_list[i].client, oauth_request_list[i]) == False
        assert validator.validate_scopes('', ['fake_scopes', f'faker_scope{i + 1}'], oauth_request_list[i].client, oauth_request_list[i]) == False
