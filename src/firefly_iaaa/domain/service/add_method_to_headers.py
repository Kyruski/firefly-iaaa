from __future__ import annotations

import firefly as ff


class AddMethodToHeaders(ff.DomainService):
    _kernel: ff.Kernel = None
    
    def __call__(self, incoming_kwargs: dict, http_method: str = 'POST'):
        incoming_kwargs = self._add_headers_from_kernel(incoming_kwargs)
        try:
            headers = incoming_kwargs['headers']['http_request'].get('headers')
        except KeyError:
            headers = incoming_kwargs['headers']
        headers['method'] = http_method
        return headers

    def _add_headers_from_kernel(self, item: dict):
        if self._kernel.http_request:
            
            headers = self._kernel.http_request.get('headers', {})
            item['headers'] = item.get('headers', {})
            item['headers'].update(headers)
        return item
