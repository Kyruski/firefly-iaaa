from __future__ import annotations

import firefly as ff


class AddMethodToHeaders(ff.DomainService):
    _kernel: ff.Kernel = None
    
    def __call__(self, incoming_kwargs: dict, http_method: str = 'POST'):
        print('HEADERS Before SETTING METHOD', http_method, incoming_kwargs)
        incoming_kwargs = self._add_headers_from_kernel(incoming_kwargs)
        try:
            headers = incoming_kwargs['headers']['http_request'].get('headers')
        except KeyError:
            headers = incoming_kwargs['headers']
        print('WE HAVE HEADERS1111', headers)
        print('WE HAVE methof', http_method)
        headers['method'] = http_method
        print('WE HAVE HEADERS1111', headers)
        print('WE HAVE methof', http_method)
        print('HEADERS AFTER SETTING METHOD', headers)
        return headers

    def _add_headers_from_kernel(self, item: dict):
        if self._kernel.http_request:
            
            print('HTTP_REQUEST', self._kernel.http_request)
            headers = self._kernel.http_request.get('headers', {})
            print('WE GOT KERNEL STUFF', self._kernel)
            print('WE GOT KERNEL STUFF', dir(self._kernel))
            print('WE GOT KERNEL STUFF', self._kernel.__dict__)
            print('WE GOT HEADERS STUFF', headers)
            print('WE GOT HEADERS STUFF', dir(headers))
            item['headers'] = item.get('headers', {})
            item['headers'].update(headers)
        return item
