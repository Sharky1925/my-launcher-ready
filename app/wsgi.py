try:
    from . import create_app
except ImportError:  # pragma: no cover - fallback when running from app/ cwd
    from __init__ import create_app

app = create_app()
