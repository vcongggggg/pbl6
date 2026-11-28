#!/bin/sh
set -e

python - <<'PY'
import os
import secrets
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "bookstore.settings")
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()
user, _ = User.objects.get_or_create(
    username="demo_admin",
    defaults={"email": "admin@bookie.local", "is_staff": True},
)
if not user.is_staff:
    user.is_staff = True
if not user.email:
    user.email = "admin@bookie.local"
user.set_password(os.environ.get("DEMO_ADMIN_PASSWORD") or secrets.token_urlsafe(18))
user.save()
PY

exec python manage.py runserver "0.0.0.0:${PORT:-5000}"
