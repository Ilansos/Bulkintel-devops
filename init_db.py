#!/usr/bin/env python
"""
Run migrations, then make sure a super-user exists.
If the database isn’t ready yet, wait 20 s and retry until it is.
Safe to run repeatedly (idempotent).
"""
import os
import sys
import time
import django
import logging
from django.core.management import call_command
from django.contrib.auth import get_user_model
from django.db import connections
from django.db.utils import OperationalError
from django.apps import apps

# Set up logger
logging.basicConfig(stream=sys.stdout, 
                    level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# 0. Wait for the DB
# -----------------------------------------------------------------------------
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "bulkintel.settings")
django.setup()

db_conn = connections["default"]
logger.info("⏳ Waiting for database …")

while True:
    try:
        db_conn.ensure_connection()   # opens a real connection or raises
        logger.info("✅  Database is up!")
        break
    except OperationalError as exc:
        logger.error(f"🔄  DB unavailable ({exc}); retrying in 20 s …")
        time.sleep(20)

# -----------------------------------------------------------------------------
# 1. Run migrations (idempotent)
# -----------------------------------------------------------------------------
call_command("makemigrations", interactive=False, verbosity=1)
call_command("migrate", interactive=False, verbosity=1)

# -----------------------------------------------------------------------------
# 2. Ensure a super-user exists (idempotent)
# -----------------------------------------------------------------------------
User = get_user_model()
username = os.getenv("DJANGO_SU_NAME",  "admin")
email    = os.getenv("DJANGO_SU_EMAIL", "admin@example.com")
password = os.getenv("DJANGO_SU_PASS",  "change-me")

if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username=username, email=email, password=password)
    logger.info(f"✅  Created initial super-user “{username}”")
else:
    logger.info(f"ℹ️  Super-user “{username}” already exists – nothing to do.")

try:
    AllowedEmail = apps.get_model("auth_app", "AllowedEmail")   # <app-label>, <model-name>
except LookupError:
    logger.warning("⚠️  auth_app.AllowedEmail model not found – skipping allow-list step")
else:
    if not AllowedEmail.objects.filter(email=email).exists():
        AllowedEmail.objects.create(email=email)
        logger.info(f"✅  Added '{email}' to auth_app_allowedemail allow-list")
    else:
        logger.info(f"ℹ️  '{email}' already present in the allow-list")
