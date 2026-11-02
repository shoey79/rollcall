#!/usr/bin/with-contenv bashio
bashio::log.info "Starting Rollcall..."
exec python3 -u /app/main.py
