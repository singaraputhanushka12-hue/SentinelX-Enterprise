import os

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import Response

class ApiBoundary:
    def __init__(self, app, *, prefix, origin_setting, default_origins, max_body):
        self.app = app
        self.prefix = prefix
        self.origins = set(os.getenv(origin_setting, default_origins).split(','))
        self.max_body = max_body

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope['path'].startswith(self.prefix):
            await self.app(scope, receive, send)
            return
        if scope['method'] not in ('GET','HEAD','OPTIONS'):
            headers = Headers(scope=scope)
            origin = headers.get('origin')
            if origin and origin not in self.origins:
                await Response(status_code=403)(scope, receive, send)
                return
            size = headers.get('content-length','')
            if not size.isascii() or not size.isdecimal() or len(size)>10 or int(size)>self.max_body:
                await Response(status_code=413)(scope, receive, send)
                return
        async def prevent_cache(message):
            if message['type'] == 'http.response.start':
                MutableHeaders(scope=message)['Cache-Control'] = 'no-store'
            await send(message)
        await self.app(scope, receive, prevent_cache)

