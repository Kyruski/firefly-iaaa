from __future__ import annotations

import firefly as ff


class AddHeadersFromKernel(ff.DomainService):
    _kernel: ff.Kernel = None
    
    def __call__(self, item: dict):
        http_request = self._kernel.http_request
        print('HTTP_REQUEST', http_request)
        headers = http_request['headers']
        print('WE GOT KERNEL STUFF', self._kernel)
        print('WE GOT KERNEL STUFF', dir(self._kernel))
        print('WE GOT KERNEL STUFF', self._kernel.__dict__)
        print('WE GOT HEADERS STUFF', headers)
        print('WE GOT HEADERS STUFF', dir(headers))
        item['headers'] = item.get('headers', {})
        item['headers'].update(headers)
        return item
