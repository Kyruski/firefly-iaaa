from __future__ import annotations
from typing import List

import pytest
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.user import User
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError
import firefly as ff
import json

import pytest
import firefly as ff

from firefly_iaaa.domain.entity.authorization_code import AuthorizationCode
from firefly_iaaa.domain.entity.bearer_token import BearerToken
from firefly_iaaa.domain.entity.user import User

from firefly_iaaa.domain.service.oauth_provider import OauthProvider

def test_introspect_response(auth_service: OauthProvider, introspect_messages: List[ff.Message]):

    VALID_METHOD_TYPES = ['GET', 'PUT', 'POST', 'DELETE', 'HEAD', 'PATCH']
    token_status = ['active', 'expired', 'invalid']
    for i in range(6):
        for x in range(3):
            message = introspect_messages[i][token_status[x]]
            message.headers['http_method'] = 'POST'
            headers, body, status = auth_service.create_introspect_response(message)

            # is_true is this value because i % 3 == 2 means the token is missing from message
            is_true = (i % 3 != 2)
            body = json.loads(body)
            expected_status = 200 if is_true else 400

            # Check for the correct status, as well as if error exists and if token is active
            assert status == expected_status
            assert (body.get('error') is None) == is_true
            assert (body.get('active') is None) != is_true

            # Check that active is True or false (x == 0 means only 'active' tokens, and not 'expired' or 'invalid')
            if is_true:
                assert body.get('active') == (x == 0)
                if x == 0:
                    # Check for the correct token type
                    if i % 3 == 0:
                        assert body.get('token_type') == 'refresh_token'
                    elif i % 3 == 1:
                        assert body.get('token_type') == 'access_token'

            # Check state exists when not valid
            if not is_true:
                assert body.get('state') == 'abc'

    # Check all http_methods except for POST fail
    for method in VALID_METHOD_TYPES:
        if method == 'POST':
            continue
        message = introspect_messages[0]['active']
        message.headers['http_method'] = method
        headers, body, status = auth_service.create_introspect_response(message)
        body = json.loads(body)
        assert body.get('error') == 'invalid_request'
        assert body.get('error_description') == f'Unsupported request method {method}'


def test_introspect_missing_data(auth_service: OauthProvider, bearer_messages_second_list: List[ff.Message]):

    message = bearer_messages_second_list[-1]
    message.headers['http_method'] = 'POST'
    headers, body, status = auth_service.create_introspect_response(message)
    body = json.loads(body)
    assert (body.get('error') is None)

    # Check for various missing attributes from message
    for i in range(17):
        message = bearer_messages_second_list[i]
        message.headers['http_method'] = 'POST'
        if i == 0:
            message.code_challenge = None
        if i == 1:
            message.password = None
        if i == 2:
            message.response_type = None
        if i == 3:
            message.access_token = None
        if i == 4:
            message.client_id = None
        if i == 5:
            message.client_secret = None
        if i == 6:
            message.code_challenge_method = None
        if i == 7:
            message.code = None
        if i == 8:
            message.username = None
        if i == 9:
            message.grant_type = None
        if i == 10:
            message.redirect_uri = None
        if i == 11:
            message.code_verifier = None
        if i == 12:
            message.scopes = None
        if i == 13:
            message.password = None
            message.client_secret = None
        if i == 14:
            message.token_type_hint = None
        if i == 15:
            message.state = None
        if i == 16:
            message.refresh_token = None

        headers, body, status = auth_service.create_introspect_response(message)
        body = json.loads(body)
        # Check error is missing from the body response when a token was supplied (i % 3 != 2)
        # Make sure error in body when missing authentication parameters (password and client secret)
        assert (body.get('error') is None) == (i % 3 != 2)


@pytest.fixture()
def introspect_messages(message_factory, bearer_tokens_list: List[dict], user_list: List[User]):
    messages = []
    status = ['active', 'expired', 'invalid']
    for i in range(6):
        message_group = {}
        for x in range(3):
            bearer_token = bearer_tokens_list[i][status[x]]
            message = message_factory.query(
                name='a1b2c3',
                data={'headers': {'http_method': 'GET', 'uri': bearer_token.client.default_redirect_uri},
                    'username': user_list[i].email if (i % 2 == 0 and i != 5) else None,
                    'password': f'password{i + 1}',
                    "client_id": bearer_token.client.client_id,
                    "client_secret": bearer_token.client.client_secret if (i % 2 == 1 and i != 5) else None,
                    "state": 'abc',
                    "token": bearer_token.refresh_token if (i % 3) == 0 else bearer_token.access_token if (i % 3) == 1 else None,
                    "user": None,
                    "token_type_hint": 'Bearer',
                }
            )
            message_group[status[x]] = message
        messages.append(message_group)
    return messages
