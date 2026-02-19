import sys
try:
    from . import create_app
except ImportError:  # pragma: no cover - fallback when running from app/ cwd
    from __init__ import create_app

app = create_app()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f" * Running on http://127.0.0.1:{port}")
    app.run(host='127.0.0.1', port=port, debug=False)
