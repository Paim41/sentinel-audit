import os

os.environ.setdefault("SENTINEL_SERVERLESS", "true")

from app import create_app


app = create_app(os.environ.get("FLASK_ENV", "production").lower())
