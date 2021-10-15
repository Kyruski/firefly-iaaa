from __future__ import annotations
from typing import List

from oauthlib.common import Request

from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.service.request_validator import OauthRequestValidators


def test_revoke_token(validator: OauthRequestValidators, oauth_request_list: List[Request], bearer_tokens_list: List[dict], registry):
    for i in range(6):
        token_types = ['refresh_token', 'access_token', None]
        bearer_token = bearer_tokens_list[i]['active']
        token_type_hint = token_types[i % 3]

        # Set token to access or refresh and search for token
        if i < 3:
            token = bearer_token.access_token
            found_token = registry(BearerToken).find(lambda x: x.access_token == token)
        else:
            token = bearer_token.refresh_token
            found_token = registry(BearerToken).find(lambda x: x.refresh_token == token)

        # Check the token is valid at first
        assert found_token.is_valid == True
        assert found_token.is_access_valid == True

        # Check an invalid token doesn't invalidate the found token
        validator.revoke_token('token', token_type_hint, oauth_request_list[i])
        assert found_token.is_valid == True
        assert found_token.is_access_valid == True

        # Correctly revoke token
        validator.revoke_token(token, token_type_hint, oauth_request_list[i])

        if i < 3:
            # i < 3 is access token. Check to make sure refresh token not invalidated
            assert found_token.is_valid == True
            assert found_token.is_access_valid == False
            validator.revoke_token(bearer_token.refresh_token, token_type_hint, oauth_request_list[i])

            # Check the refresh token invalidated after passing it
            assert found_token.is_valid == False
            assert found_token.is_access_valid == False
        else:
            # Check to make sure a revoked refresh token invalidates both
            assert found_token.is_valid == False
            assert found_token.is_access_valid == False
        
        #Checking to make sure it's not affecting other tokens
        next_token = registry(BearerToken).find(lambda x: x.refresh_token == bearer_tokens_list[i + 1]['active'].refresh_token)
        assert next_token.is_valid == True
        assert next_token.is_access_valid == True
