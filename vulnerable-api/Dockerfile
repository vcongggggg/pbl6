FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    DJANGO_ENV=development \
    ALLOWED_HOSTS=*

WORKDIR /app

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run collectstatic safely
RUN python manage.py collectstatic --noinput || true

EXPOSE 5000

CMD ["python", "manage.py", "runserver", "0.0.0.0:5000"]
