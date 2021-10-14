from __future__ import annotations

import firefly as ff
import firefly_iaaa.domain as domain
import firefly_iaaa.infrastructure as infra


@ff.rest(
    '/iaaa/create_token', method='POST', tags=['public']
)
@ff.command_handler('firefly_iaaa.TokenCreation')
class OauthTokenCreationService(ff.ApplicationService):
    _oauth_provider: infra.OauthProvider = None
    _kernel: ff.Kernel = None
    _message_factory: ff.MessageFactory = None

    def __call__(self, **kwargs):
        message = self._make_message(kwargs)

        headers, body, status =  self._oauth_provider.create_token_response(message)
        # if status == 200:
        #     body = json.loads(body)
        # #? Add headers?

        return body

    def _get_client_id(self, client_id):
        return client_id or self._kernel.user.id

    def _make_message(self, incoming_kwargs: dict):
        message_body = {
            'headers': incoming_kwargs.get('headers'),
            'grant_type': incoming_kwargs.get('grant_type'),
            "client_id": self._get_client_id(incoming_kwargs.get('client_id')),
            "state": incoming_kwargs.get('state')
        }

        if incoming_kwargs.get('username'):
            message_body['username'] = incoming_kwargs.get('username') 
        if incoming_kwargs.get('password'):
            message_body['password'] = incoming_kwargs.get('password') 
        if incoming_kwargs.get('client_secret'):
            message_body['client_secret'] = incoming_kwargs.get('client_secret') 
        if incoming_kwargs.get('code'):
            message_body['code'] = incoming_kwargs.get('code') 
        if incoming_kwargs.get('token'):
            message_body['token'] = incoming_kwargs.get('token')

        return self._message_factory.query(
            name='a1b2c3', #!??????
            data=message_body
        )

    # def _get_token_access_rights(self, event: dict):
    #     user: domain.User = self._registry(domain.User).find(event['request']['userAttributes']['sub'])
    #     if user is None:
    #         self.info('No record for user "%s"', event['request']['userAttributes']['sub'])
    #         return event

    #     scopes = []
    #     for role in user.roles:
    #         scopes.extend(list(map(str, role.scopes)))

    #     event['response'] = {
    #         'claimsOverrideDetails': {
    #             'groupOverrideDetails': {
    #                 'groupsToOverride': scopes,
    #             }
    #         }
    #     }

    #     return event



# @ff.command_handler('firefly_iaaa.TokenResponse_AuthCode')
# class HandleAuthCode(BaseOauthTokenResponseService):

#     #! Needs
#     # client_id
#         # password/username or client_secret
#     # grant_type
#     # code


#     def __call__(self, **kwargs):
#     # def __call__(self, event: dict, **kwargs):
#         message = self._make_message(kwargs)

#         headers, body, status =  self._oauth_provider.create_token_response(message)

# @ff.command_handler('firefly_iaaa.TokenResponse_Password')
# class HandlePassword(BaseOauthTokenResponseService):

#     #! Needs
#     # client_id
#     # password/username
#     # grant_type



#     def __call__(self, **kwargs):
#     # def __call__(self, event: dict, **kwargs):
#         message = self._make_message(kwargs)

#         headers, body, status =  self._oauth_provider.create_token_response(message)

# @ff.command_handler('firefly_iaaa.TokenResponse_ClientCredentials')
# class HandleClientCredentials(BaseOauthTokenResponseService):

#     #! Needs
#     # client_id
#     # client_secret
#     # grant_type


#     def __call__(self, **kwargs):
#     # def __call__(self, event: dict, **kwargs):
#         message = self._make_message(kwargs)

#         headers, body, status =  self._oauth_provider.create_token_response(message)

# @ff.command_handler('firefly_iaaa.TokenResponse_RefreshToken')
# class HandleRefreshToken(BaseOauthTokenResponseService):

#     #! Needs
#     # client_id
#         # client_secret or password/username
#     # grant_type


#     def __call__(self, **kwargs):
#     # def __call__(self, event: dict, **kwargs):
#         message = self._make_message(kwargs)

#         headers, body, status =  self._oauth_provider.create_token_response(message)
#         # if status == 200:
#         #     body = json.loads(body)
#         # #? Add headers?

#         return body

# # @ff.command_handler('firefly_aws.TokenResponse_HostedAuth') #! Hosted auth?
# # class HandleHostedAuth(BaseOauthTokenResponseService):
# #     _registry: ff.Registry = None

# #     def __call__(self, event: dict, **kwargs):
# #         return self._get_token_access_rights(event)
