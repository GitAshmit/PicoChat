#!/bin/sh
# Builds CipherChat, creates the log directory and TLS key if missing,
# then starts the server.   Usage: ./run_server.sh [port]
set -e
cd "$(dirname "$0")"

make -s all certs
mkdir -p logs
chmod 700 logs

echo "starting server (Ctrl+C to stop); log: logs/cipherchat.log"
exec ./server "${1:-5000}"
