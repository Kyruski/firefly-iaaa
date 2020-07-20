from __future__ import annotations

import firefly as ff


@ff.query_handler()
class GetTokenAccessRights(ff.ApplicationService):
    _repository: ff.Repository = None

    def __call__(self, event: dict, **kwargs):
        print(event)
        event['response'] = {
            'groupOverrideDetails': {
                'groupsToOverride': ['groupA', 'groupB'],
                'iamRolesToOverride': ['distributed_events.Activity.write', 'distributed_events.Activity.admin']
            }
        }
        return event
