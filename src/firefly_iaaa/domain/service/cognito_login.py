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

import os

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
        print('aaaa', resp)
        print('aaaa', msg)
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
                    'token_type': resp['AuthenticationResult']['TokenType'],
                    'decoded_id_token': self._jwt_decoder.decode(resp['AuthenticationResult']['IdToken'])
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
        print('a')
        try:
            print('b')
            print('RIGHT BEFORE INITIATE AUTH', os.environ)
            resp = client.admin_initiate_auth(
                        UserPoolId=os.environ['USER_POOL_ID'],
                        ClientId=os.environ['CLIENT_ID'],
                        AuthFlow='ADMIN_NO_SRP_AUTH',
                        AuthParameters={
                            'USERNAME': username,
                            'PASSWORD': password,
                        },
                        ClientMetadata={
                        'username': username,
                        'password': password,
                    })
            print('c')
        except client.exceptions.NotAuthorizedException:
            print('d')
            return None, 'The username or password is incorrect'
        except client.exceptions.UserNotConfirmedException:
            print('e')
            return None, 'User is not confirmed'
        except KeyError as e:
            return None, f'Key Error: {e.__str__()}'
        except Exception as e:
            print('f', e.__str__())
            print('f', e.__dict__)
            return None, e.__str__()
        print('g')
        return resp, None
