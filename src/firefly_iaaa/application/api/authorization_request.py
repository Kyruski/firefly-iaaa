from __future__ import annotations

import firefly as ff
import urllib
import ast
import base64
import firefly_iaaa.domain as domain
from firefly_iaaa.application.api.generic_oauth_endpoint import GenericOauthEndpoint

#! Secured?
@ff.rest('/iaaa/authorize', method='GET', tags=['public'], secured=False)
class OauthAuthorizationRequestService(GenericOauthEndpoint):
    _registry: ff.Registry = None
    _subdomain: str = None

    def __call__(self, **kwargs):
        kwargs = self._fix_email(kwargs)
        message = self._make_message(kwargs) #! check more

        resp = self._oauth_provider.validate_pre_auth_request(message)
        return self._make_response(forwarding_address=self._make_local_response(*resp))

    def _make_message(self, incoming_kwargs: dict):
        headers = self._add_method_to_headers(incoming_kwargs, 'GET')
        message_body = {
            'headers': headers,
            'client_id': self._get_client_id(incoming_kwargs.get('client_id')),
            'state': incoming_kwargs.get('state'),
            'response_type': incoming_kwargs.get('response_type'),
            'code_challenge': incoming_kwargs.get('code_challenge'),
        }

        if incoming_kwargs.get('username'):
            message_body['username'] = incoming_kwargs.get('username') 
        if incoming_kwargs.get('password'):
            message_body['password'] = incoming_kwargs.get('password') 
        if incoming_kwargs.get('client_secret'):
            message_body['client_secret'] = incoming_kwargs.get('client_secret')
        if incoming_kwargs.get('cohort_id'):
            message_body['cohort_id'] = incoming_kwargs.get('cohort_id')

        return self._message_factory.query(
            name='OauthAuthorizationRequestMessage',
            data=message_body
        )

    def _get_cohort_name(self, cohort_id: str):
        if cohort_id:
            cohort = self._registry(domain.Cohort).find(lambda x: x.id == cohort_id)
            if cohort:
                return cohort.name
        return None


    def _make_local_response(self, scopes, credentials, credentials_key):
        cohort_name = self._get_cohort_name(credentials['request']['body'].get('cohort_id'))
        resp = {
            'redirect_uri': credentials.get('redirect_uri'),
            'client_id': credentials.get('client_id'),
            'scopes': scopes,
            'credentials_key': credentials_key,
            'response_type': credentials.get('response_type'),
            'client': {'tenant': credentials['request']['client']['tenant_name'], 'cohort': cohort_name or ''}
        }
        if 'code_challenge' in credentials:
            resp['code_challenge'] = credentials['code_challenge']
        if 'code_challenge_method' in credentials:
            resp['code_challenge_method'] = credentials['code_challenge_method']
        # if 'claims' in credentials:
        #     kwargs['claims'] = json.dumps(credentials['claims'])
        redirect_url = f'https://{self._subdomain}.pwrlab.com/authorize?' #!!!!

        for k, v in resp.items():
            if not v:
                continue
            if k == 'redirect_uri':
                v = base64.b64encode(v.encode('utf-8'))
            val = urllib.parse.quote(str(v), safe='')
            redirect_url += f'{k}={val}&'
        return redirect_url[0:-1]


#! Secured?
@ff.rest(
    '/iaaa/authorize', method='POST', tags=['public'], secured=False
)
class OauthCreateAuthorizationService(GenericOauthEndpoint):

    def __call__(self, **kwargs):
        kwargs = self._fix_email(kwargs)
        message = self._make_message(kwargs) #! check more
        
        access_token = self._grab_token_from_headers()

        self._set_user_from_token(access_token, message.client_id)

        headers, body, status = self._oauth_provider.validate_post_auth_request(message)
        if not headers and not body and not status:
            raise ff.UnauthorizedError()
        if status == 302 and 'Location' in headers:
            body = body or {}
            body['redirect'] = headers['Location']
        return self._make_response(body)


    def _make_message(self, incoming_kwargs: dict):
        headers = self._add_method_to_headers(incoming_kwargs)
        redirect_uri = self._get_redirect_uri(incoming_kwargs)
        message_body = {
            'headers': headers,
            'state': incoming_kwargs.get('state'),
            'redirect_uri': redirect_uri,
            'client_id': incoming_kwargs.get('client_id'),
            'scopes': incoming_kwargs.get('scopes'),
            'credentials_key': incoming_kwargs.get('credentials_key'),
            'response_type': incoming_kwargs.get('response_type')
        }


        return self._message_factory.query(
            name='OauthCreateAuthorizationMessage',
            data=message_body
        )

    @staticmethod
    def _get_redirect_uri(incoming_kwargs: dict):

        redirect_uri = incoming_kwargs.get('redirect_uri')
        if not redirect_uri:
            raise ff.UnauthorizedError('Missing redirect_uri')
        redirect_uri = urllib.parse.unquote(redirect_uri)
        redirect_uri = base64.b64decode(ast.literal_eval(redirect_uri))
        return redirect_uri.decode('utf-8')

    def _grab_token_from_headers(self):
        for k, v in self._kernel.http_request['headers'].items():
            if k.lower() == 'authorization':
                if not v.lower().startswith('bearer'):
                    raise ff.UnauthorizedError()
                return v.split(' ')[-1]
        raise ff.UnauthorizedError()

    def _set_user_from_token(self, access_token: str, client_id: str):
        bearer_token = self._registry(domain.BearerToken).find(lambda x: x.access_token == access_token)
        client = self._registry(domain.Client).find(lambda x: x.client_id == client_id)
        if not client or not bearer_token:
            ff.UnauthorizedError()
        if not bearer_token.validate_access_token(access_token, client):
            ff.UnauthorizedError('Invalid access token')
        user = bearer_token.user
        decoded_token = self._decode_token(access_token)
        if not decoded_token:
            ff.UnauthorizedError('Invalid access_token/client combination')
        self._kernel.user = ff.User(id=user.sub, scopes=decoded_token['scope'].split(' '), tenant=user.tenant_id, token=decoded_token)
