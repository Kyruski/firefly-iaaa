from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
import pytest


def test_validate_code(validator, oauth_request_list, auth_codes_list, registry):
    for i in range(4):
        for x in range(3):
            code_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
            auth_code = auth_codes_list[i][code_selector]
            assert oauth_request_list[i].user is None
            assert oauth_request_list[i].scopes is None
            assert oauth_request_list[i].claims is None
            assert validator.validate_code('', auth_code.code, oauth_request_list[i].client, oauth_request_list[i]) == (x == 0)
            assert (oauth_request_list[i].user == auth_code.user) == (x == 0)
            assert (oauth_request_list[i].scopes == auth_code.scopes) == (x == 0)
            assert oauth_request_list[i].claims is None

            oauth_request_list[i].user = None
            oauth_request_list[i].scopes = None
            oauth_request_list[i].claims = None

            assert oauth_request_list[i].user is None
            assert oauth_request_list[i].scopes is None
            assert oauth_request_list[i].claims is None
            assert validator.validate_code('', auth_code.code, oauth_request_list[(i + 1) % 4].client, oauth_request_list[i]) == False #Check for wrong client
            assert oauth_request_list[i].user is None

            oauth_request_list[i].user = None
            oauth_request_list[i].scopes = None
            oauth_request_list[i].claims = None

            auth = registry(AuthorizationCode).find(auth_code.id_)
            auth.claims = {'data': 'not empty'}

            assert validator.validate_code('', auth_code.code, oauth_request_list[i].client, oauth_request_list[i]) == (x == 0)
            assert (oauth_request_list[i].user == auth_code.user) == (x == 0)
            assert (oauth_request_list[i].scopes == auth_code.scopes) == (x == 0)
            assert (oauth_request_list[i].claims is not None) == (x == 0)

            oauth_request_list[i].user = None
            oauth_request_list[i].scopes = None
            oauth_request_list[i].claims = None
