FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    DJANGO_ENV=development \
    ALLOWED_HOSTS=*

WORKDIR /app

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Migrate SQLite DB, seed demo account for OWASP API3/DLP endpoints, collect static, drop to non-root (INFRA-PBL6-001)
RUN python manage.py migrate --noinput \
    && python -c "import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','bookstore.settings'); django.setup(); from django.contrib.auth import get_user_model; U=get_user_model(); u,_=U.objects.get_or_create(username='demo_admin', defaults={'email':'admin@bookie.local','is_staff':True}); u.set_password('DemoPass#2026'); u.save()" \
    && (python manage.py collectstatic --noinput || true) \
    && groupadd --system --gid 1001 appuser \
    && useradd --system --uid 1001 --gid appuser --home-dir /app --shell /sbin/nologin appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

CMD ["python", "manage.py", "runserver", "0.0.0.0:5000"]
