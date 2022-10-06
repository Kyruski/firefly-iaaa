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
from firefly_iaaa import domain
import boto3



class CognitoClient(ff.DomainService, ff.LoggerAware):
    _decode_token: domain.DecodeToken = None
    _kernel: ffd.Kernel = None
    _client = boto3.client('cognito-idp')




    def login(self, username: str, password: str):
        
        resp, msg = self._initiate_auth(username, password)

        if msg != None:
            return {'message': msg, 
                    'error': 'No user exists', 'success': False, 'data': None}
        if resp.get('AuthenticationResult'):
            return {
                'message': 'success', 
                'error': '',
                'success': True, 
                'data': {
                    'id_token': resp['AuthenticationResult']['IdToken'],
                    'refresh_token': resp['AuthenticationResult']['RefreshToken'],
                    'access_token': resp['AuthenticationResult']['AccessToken'],
                    'expires_in': resp['AuthenticationResult']['ExpiresIn'],
                    'token_type': resp['AuthenticationResult']['TokenType'],
                    # 'decoded_id_token': self._decode_token(resp['AuthenticationResult']['IdToken'])
                }
            }
        else:
            return {
                'error': 'Something went wrong, no authentication results', 
                'success': False, 
                'data': None,
                'message': 'error'
            }


    def register(self, username: str, password: str, **kwargs):
        resp, msg = self._sign_up(username, password, kwargs)

        if msg != None:
            return {'message': msg, 
                    'error': 'No user exists', 'success': False, 'data': None}
        if resp.get('AuthenticationResult'):
            return {
                'message': 'success', 
                'error': '',
                'success': True, 
                'data': {
                    'id_token': resp['AuthenticationResult']['IdToken'],
                    'refresh_token': resp['AuthenticationResult']['RefreshToken'],
                    'access_token': resp['AuthenticationResult']['AccessToken'],
                    'expires_in': resp['AuthenticationResult']['ExpiresIn'],
                    'token_type': resp['AuthenticationResult']['TokenType'],
                    # 'decoded_id_token': self._decode_token(resp['AuthenticationResult']['IdToken'])
                }
            }
        else:
            return {
                'error': 'Something went wrong, no authentication results', 
                'success': False, 
                'data': None,
                'message': 'error'
            }


    def _initiate_auth(self, username, password):
        try:
            resp = self._client.initiate_auth(
                        ClientId=os.environ['CLIENT_ID'],
                        AuthFlow='USER_PASSWORD_AUTH',
                        AuthParameters={
                            'USERNAME': username,
                            'PASSWORD': password,
                        },
                        ClientMetadata={
                        'username': username,
                        'password': password,
                    })

        except self._client.exceptions.NotAuthorizedException:
            return None, 'The username or password is incorrect'
        except self._client.exceptions.UserNotConfirmedException:
            return None, 'User is not confirmed'
        except KeyError as e:
            return None, f'Key Error: {e.__str__()}'
        except Exception as e:
            return None, e.__str__()
        return resp, None


    def _sign_up(self, username, password, kwargs):
        #try cognito login, if not, try pwrlab login, if not, make pwrlab, make cognito, update pwrlab
        user_attrs = [
            {
            'Name': k,
            'Value': v
            } for k, v in kwargs.items() if k in domain.User
        ]
        try:
            resp = self._client.sign_up(
                ClientId=os.environ['CLIENT_ID'],
                Username=username,
                Password=password,
                UserAttributes=user_attrs
            )
            print(resp)
            if 'UserSub' in resp:
                #DO somethng
                return resp['UserSub']
        except self._client.exceptions.NotAuthorizedException:
            return None, 'The username or password is incorrect'
        except self._client.exceptions.UserNotConfirmedException:
            return None, 'User is not confirmed'
        except KeyError as e:
            return None, f'Key Error: {e.__str__()}'
        except Exception as e:
            return None, e.__str__()
        return resp, None

