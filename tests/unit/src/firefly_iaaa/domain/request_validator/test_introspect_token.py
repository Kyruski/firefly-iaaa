from __future__ import annotations
import os
from typing import List


from oauthlib.common import Request
from firefly_iaaa.domain.entity.bearer_token import BearerToken

from firefly_iaaa.infrastructure.service.request_validator import OauthlibRequestValidators


def test_introspect_token(validator: OauthlibRequestValidators, oauth_request_list: List[Request], bearer_tokens_list: List[BearerToken]):
    token_status = ['active', 'expired', 'invalid']
    for i in range(6):
        for x in range(3):
            for token_type in ['refresh_token', 'access_token', None]:
                bearer_token = bearer_tokens_list[i][token_status[x]]
                assert_request_empty(oauth_request_list[i])
                resp = validator.introspect_token(bearer_token.refresh_token, token_type, oauth_request_list[i])

                # Check for refresh token
                if x == 0:
                    # Check that all claims exist
                    # Check the token on the request has been set
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
                    assert oauth_request_list[i].token['iss'] == os.environ['ISSUER']
                    assert oauth_request_list[i].token['jti'] is not None and type(oauth_request_list[i].token['jti']) == type('')

                    # Check the response is correct
                    assert resp['active'] == bearer_token.validate_refresh_token(bearer_token.refresh_token, oauth_request_list[i].client)
                    assert resp['scope'] == bearer_token.scopes
                    assert resp['client_id'] == bearer_token.client.client_id
                    assert resp['username'] == bearer_token.user.email or bearer_token.user.preferred_username
                    assert resp['token_type'] == 'refresh_token'
                    assert resp['exp'] == bearer_token.expires_at.timestamp()
                    assert resp['iat'] == bearer_token.created_at.timestamp()
                    assert resp['nbf'] == bearer_token.activates_at.timestamp()
                    assert resp['sub'] == bearer_token.user.sub
                    assert resp['aud'] == bearer_token.client.client_id
                    assert resp['iss'] == os.environ['ISSUER']
                    assert resp['jti'] is not None and type(oauth_request_list[i].token['jti']) == type('')
                else:
                    # Check that invalid/expired tokens return none
                    assert resp is None
                reset_and_assert_empty(oauth_request_list[i])
                resp = validator.introspect_token(bearer_token.access_token, token_type, oauth_request_list[i])

                # Check for access token
                if x == 0:
                    # Check that all claims exist
                    # Check the token on the request has been set
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
                    assert oauth_request_list[i].token['iss'] == os.environ['ISSUER']
                    assert oauth_request_list[i].token['jti'] is not None and type(oauth_request_list[i].token['jti']) == type('')

                    # Check the response is correct
                    assert resp['active'] == bearer_token.validate_access_token(bearer_token.access_token, oauth_request_list[i].client)
                    assert resp['scope'] == bearer_token.scopes
                    assert resp['client_id'] == bearer_token.client.client_id
                    assert resp['username'] == bearer_token.user.email or bearer_token.user.preferred_username
                    assert resp['token_type'] == 'access_token'
                    assert resp['exp'] == bearer_token.expires_at.timestamp()
                    assert resp['iat'] == bearer_token.created_at.timestamp()
                    assert resp['nbf'] == bearer_token.activates_at.timestamp()
                    assert resp['sub'] == bearer_token.user.sub
                    assert resp['aud'] == bearer_token.client.client_id
                    assert resp['iss'] == os.environ['ISSUER']
                    assert resp['jti'] is not None and type(oauth_request_list[i].token['jti']) == type('')
                else:
                    # Check that invalid/expired tokens return none
                    assert resp is None
                reset_and_assert_empty(oauth_request_list[i])

                # Check a bad/non-existent token returns None
                resp = validator.introspect_token('bearer_token.access_token', token_type, oauth_request_list[i])
                assert_request_empty(oauth_request_list[i])
                assert resp == None

def assert_request_empty(request):
    assert request.token is None

def reset_request(request):
    request.token = None

def reset_and_assert_empty(request):
    reset_request(request)
    assert_request_empty(request)