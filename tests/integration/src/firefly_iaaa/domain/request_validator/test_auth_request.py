from __future__ import annotations
from typing import List

import pytest
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.client import Client
from firefly_iaaa.domain.entity.user import User
from oauthlib.oauth2.rfc6749.errors import MissingClientIdError, MissingCodeChallengeError, MissingResponseTypeError
import firefly as ff

from firefly_iaaa.infrastructure.service.oauth_provider import OauthProvider

def test_auth_request(auth_service: OauthProvider, bearer_messages_list: List[ff.Message]):

    token_status = ['active', 'expired', 'invalid']
    for i in range(6):
        for x in range(3):
            message = bearer_messages_list[i][token_status[x]]
            scopes, credentials, credentials_key = auth_service.validate_pre_auth_request(message)

            # Check the credentials client_id is correct
            assert credentials['client_id'] == message.client_id

            setattr(message, 'credentials_key', credentials_key)
            headers, body, status = auth_service.validate_post_auth_request(message)

            uri = headers['Location']
            # Make sure it's a redirection status
            assert status == 302
            # Make sure it includes state in the uri
            assert 'state=abc' in uri

            # Check that the respective code or access token in uri
            if i % 2 == 0:
                assert 'code=' in uri
            else:
                assert 'access_token=' in uri


def test_auth_request_missing_data(auth_service: OauthProvider, bearer_messages_second_list: List[ff.Message]):

    # Check a missing/invalid credentials key ('abc' in this case) does not authenticate
    message = bearer_messages_second_list[-1]
    scopes, credentials, credentials_key = auth_service.validate_pre_auth_request(message)
    assert credentials['client_id'] == message.client_id
    setattr(message, 'credentials_key', 'abc')
    headers, body, status = auth_service.validate_post_auth_request(message)
    assert_is_none(headers, body, status)

    message = bearer_messages_second_list[-2]
    scopes, credentials, credentials_key = auth_service.validate_pre_auth_request(message)
    assert credentials['client_id'] == message.client_id
    headers, body, status = auth_service.validate_post_auth_request(message)
    assert_is_none(headers, body, status)

    # Check for various missing attributes from message
    for i in range(16):
        message = bearer_messages_second_list[i]
        message.headers['http_method'] = 'POST'
        if i == 0:
            # Check missing code challenge results in error
            message.code_challenge = None
            with pytest.raises(MissingCodeChallengeError):
                scopes, credentials, credentials_key = auth_service.validate_pre_auth_request(message)
            continue
        if i == 1:
            message.password = None
        if i == 2:
            message.grant_type = None
        if i == 3:
            message.access_token = None
        if i == 4:
            # Check missing client_id results in error
            message.client_id = None
            with pytest.raises(MissingClientIdError):
                scopes, credentials, credentials_key = auth_service.validate_pre_auth_request(message)
            continue
        if i == 5:
            message.client_secret = None
        if i == 6:
            message.code_challenge_method = None
        if i == 7:
            message.code = None
        if i == 8:
            message.username = None
        if i == 9:
            # Check missing response_type results in error
            message.response_type = None
            with pytest.raises(MissingResponseTypeError):
                scopes, credentials, credentials_key = auth_service.validate_pre_auth_request(message)
            continue
        if i == 10:
            message.redirect_uri = None
        if i == 11:
            message.refresh_token = None
        if i == 12:
            message.code_verifier = None
        if i == 13:
            message.scopes = None
        if i == 14:
            message.state = None
        if i == 15:
            message.token_type_hint = None


        scopes, credentials, credentials_key = auth_service.validate_pre_auth_request(message)
        assert credentials['client_id'] == message.client_id
        setattr(message, 'credentials_key', credentials_key)
        headers, body, status = auth_service.validate_post_auth_request(message)


        uri = headers['Location']
        assert status == 302

        # Check that state in uri UNLESS state isn't provided
        if i != 14:
            assert 'state=abc' in uri

        # Check that the respective code or access token in uri
        if i % 2 == 0:
            assert 'code=' in uri
        else:
            assert 'access_token=' in uri


def assert_is_none(headers, body, status):
    assert headers is None
    assert body is None
    assert status is None