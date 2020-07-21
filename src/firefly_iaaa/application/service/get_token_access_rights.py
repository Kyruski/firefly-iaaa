from __future__ import annotations

import firefly as ff
import firefly_iaaa.domain as domain


@ff.query_handler()
class GetTokenAccessRights(ff.ApplicationService):
    _registry: ff.Registry = None

    def __call__(self, event: dict, **kwargs):
        user: domain.User = self._registry(domain.User).find(event['request']['userAttributes']['sub'])
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
