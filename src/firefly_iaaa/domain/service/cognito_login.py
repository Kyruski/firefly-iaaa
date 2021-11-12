#  Copyright (c) 2020 JD Williams
#
#  This file is part of Firefly, a Python SOA framework built by JD Williams. Firefly is free software; you can
#  redistribute it and/or modify it under the terms of the GNU General Public License as published by the
#  Free Software Foundation; either version 3 of the License, or (at your option) any later version.
#
#  Firefly is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
#  Public License for more details. You should have received a copy of the GNU Lesser General Public
#  License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  You should have received a copy of the GNU General Public License along with Firefly. If not, see
#  <http://www.gnu.org/licenses/>.

from __future__ import annotations

from typing import Optional

import firefly as ff
from firefly import domain as ffd
import boto3

import firefly_aws.domain as domain


class CognitoLogin(ff.DomainService, ff.LoggerAware):
    _jwt_decoder: domain.JwtDecoder = None
    _kernel: ffd.Kernel = None
    _user_pool: str = None
    _client_id: str = None
    _client_secret: str = None

    def __call__(self, username: str, password: str):
        client = boto3.client('cognito-idp')
        # for field in ['username', 'password']:
        #     if event.get(field) is None:
        #         return  {
        #             'error': True, 
        #             'success': False, 
        #             'message': f'{field} is required', 
        #             'data': None
        #         }
        resp, msg = self._initiate_auth(client, username, password)
        if msg != None:
            return {'message': msg, 
                    'error': True, 'success': False, 'data': None}
        if resp.get('AuthenticationResult'):
            return {
                'message': 'success', 
                'error': False, 
                'success': True, 
                'data': {
                    'id_token': resp['AuthenticationResult']['IdToken'],
                    'refresh_token': resp['AuthenticationResult']['RefreshToken'],
                    'access_token': resp['AuthenticationResult']['AccessToken'],
                    'expires_in': resp['AuthenticationResult']['ExpiresIn'],
                    'token_type': resp['AuthenticationResult']['TokenType']
                }
            }
        else:
            return {
                'error': True, 
                'success': False, 
                'data': None,
                'message': None
            }


    def _initiate_auth(self, client, username, password):
        try:
            resp = client.admin_initiate_auth(
                        UserPoolId=self._user_pool,
                        ClientId=self._client_id,
                        AuthFlow='USER_PASSWORD_AUTH',
                        AuthParameters={
                            'USERNAME': username,
                            'PASSWORD': password,
                        },
                        ClientMetadata={
                        'username': username,
                        'password': password,
                    })
        except client.exceptions.NotAuthorizedException:
            return None, 'The username or password is incorrect'
        except client.exceptions.UserNotConfirmedException:
            return None, 'User is not confirmed'
        except Exception as e:
            return None, e.__str__()
        return resp, None
