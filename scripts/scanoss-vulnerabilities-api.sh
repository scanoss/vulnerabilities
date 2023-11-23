#!/bin/bash

##########################################
#
# This script is designed to run by Systemd SCANOSS Vulnerabilities API service.
# It rotates scanoss log file and starts SCANOSS Vulnerabilities API.
# Install it in /usr/local/bin
#
################################################################
DEFAULT_ENV="prod"
ENVIRONMENT="${1:-$DEFAULT_ENV}"
LOGFILE=/var/log/scanoss/vulnerabilities/scanoss-vulnerabilities-api-$ENVIRONMENT.log
CONF_FILE=/usr/local/etc/scanoss/vulnerabilities/app-config-${ENVIRONMENT}.json

# Rotate log
if [ -f "$LOGFILE" ] ; then
  echo "rotating logfile..."
  TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
  BACKUP_FILE=$LOGFILE.$TIMESTAMP
  cp "$LOGFILE" "$BACKUP_FILE"
  gzip -f "$BACKUP_FILE"
fi
echo > "$LOGFILE"

echo > $LOGFILE
# Start scanoss-vulnerabilities-api
echo "starting SCANOSS Vulnerabilities API"
exec /usr/local/bin/scanoss-vulnerabilities-api --json-config "$CONF_FILE" > "$LOGFILE" 2>&1