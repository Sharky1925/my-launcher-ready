import os
import sys

import asgi
from asgiref.wsgi import WsgiToAsgi
from workers import WorkerEntrypoint

APP_DIR = os.path.join(os.path.dirname(__file__), "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from __init__ import create_app  # noqa: E402

flask_app = create_app()
asgi_app = WsgiToAsgi(flask_app)


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        return await asgi.fetch(asgi_app, request.js_object, self.env)
