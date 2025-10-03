#!/bin/sh

echo "⏳ Running Django migrations / super-user check…"
python /code/init_db.py

echo "🚀  Starting Supervisord (Gunicorn + Nginx)…"
exec /usr/bin/supervisord -c /etc/supervisord.conf
