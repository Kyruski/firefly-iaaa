from __future__ import annotations
from typing import List


from oauthlib.common import Request
from firefly_iaaa.domain.entity.bearer_token import BearerToken

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidator


def test_introspect_token(validator: OauthlibRequestValidator, oauth_request_list: List[Request], bearer_tokens_list: List[BearerToken]):
    for i in range(6):
        for x in range(3):
            for token_type in ['refresh_token', 'access_token', None]:
                bearer_selector = 'active' if x == 0 else 'expired' if x == 1 else 'invalid'
                bearer_token = bearer_tokens_list[i][bearer_selector]
                assert_request_empty(oauth_request_list[i])
                validator.introspect_token(bearer_token.refresh_token, token_type, oauth_request_list[i])

                assert oauth_request_list[i].token['active'] == bearer_token.validate_refresh_token(bearer_token.refresh_token, oauth_request_list[i].client)
                assert oauth_request_list[i].token['scope'] == bearer_token.scopes
                assert oauth_request_list[i].token['client_id'] == bearer_token.client.client_id
                assert oauth_request_list[i].token['username'] == bearer_token.user.email or bearer_token.user.preferred_username
                assert oauth_request_list[i].token['token_type'] == 'refresh_token'
                assert oauth_request_list[i].token['exp'] == bearer_token.expires_at.timestamp()
                assert oauth_request_list[i].token['iat'] == bearer_token.created_at.timestamp()
                assert oauth_request_list[i].token['nbf'] == bearer_token.activates_at.timestamp()
                assert oauth_request_list[i].token['sub'] == bearer_token.user.sub
                assert oauth_request_list[i].token['aud'] == bearer_token.client.client_id
                assert oauth_request_list[i].token['iss'] == 'https://app.pwrlab.com/'
                assert oauth_request_list[i].token['jti'] is not None and type(oauth_request_list[i].token['jti']) == type('')

                reset_request(oauth_request_list[i])
                assert_request_empty(oauth_request_list[i])
                validator.introspect_token(bearer_token.access_token, token_type, oauth_request_list[i])

                assert oauth_request_list[i].token['active'] == bearer_token.validate_access_token(bearer_token.access_token, oauth_request_list[i].client)
                assert oauth_request_list[i].token['scope'] == bearer_token.scopes
                assert oauth_request_list[i].token['client_id'] == bearer_token.client.client_id
                assert oauth_request_list[i].token['username'] == bearer_token.user.email or bearer_token.user.preferred_username
                assert oauth_request_list[i].token['token_type'] == 'access_token'
                assert oauth_request_list[i].token['exp'] == bearer_token.expires_at.timestamp()
                assert oauth_request_list[i].token['iat'] == bearer_token.created_at.timestamp()
                assert oauth_request_list[i].token['nbf'] == bearer_token.activates_at.timestamp()
                assert oauth_request_list[i].token['sub'] == bearer_token.user.sub
                assert oauth_request_list[i].token['aud'] == bearer_token.client.client_id
                assert oauth_request_list[i].token['iss'] == 'https://app.pwrlab.com/'
                assert oauth_request_list[i].token['jti'] is not None and type(oauth_request_list[i].token['jti']) == type('')

                reset_request(oauth_request_list[i])
                assert_request_empty(oauth_request_list[i])
                validator.introspect_token('bearer_token.access_token', token_type, oauth_request_list[i])
                assert_request_empty(oauth_request_list[i])
                exit()

def assert_request_empty(request):
    assert request.token is None

def reset_request(request):
    request.token = None