from __future__ import annotations

import firefly as ff
import firefly_iaaa.domain as domain

import sys
import importlib.util


if 'firefly_aws' in sys.modules or importlib.util.find_spec('firefly_aws') is not None:

    class BaseAwsTokenGenerationService:
        _registry: ff.Registry = None

        def _get_token_access_rights(self, event: dict):
            user: domain.User = self._registry(domain.User).find(lambda x: (x.sub == event['request']['userAttributes']['sub']) & (x.deleted_at.is_none()))
            if user is None:
                self.info('No record for user "%s"', event['request']['userAttributes']['sub'])
                return event

            scopes = []
            for role in user.roles:
                scopes.extend(list(map(str, role.scopes)))

            event['response'] = {
                'claimsOverrideDetails': {
                    'groupOverrideDetails': {
                        'groupsToOverride': scopes,
                    }
                }
            }

            return event

    @ff.command_handler('firefly_aws.TokenGeneration_HostedAuth')
    class HandleHostedAuth(ff.ApplicationService, BaseAwsTokenGenerationService):
        _registry: ff.Registry = None

        def __call__(self, event: dict, **kwargs):
            return self._get_token_access_rights(event)


    @ff.command_handler('firefly_aws.TokenGeneration_RefreshTokens')
    class HandleRefreshTokens(ff.ApplicationService, BaseAwsTokenGenerationService):
        _registry: ff.Registry = None

        def __call__(self, event: dict, **kwargs):
            return self._get_token_access_rights(event)
