import os
import sys

APP_DIR = os.path.join(os.path.dirname(__file__), '..', 'app')
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from __init__ import create_app

app = create_app()
