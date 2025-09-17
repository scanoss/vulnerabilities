#!/bin/bash

##########################################
#
# This script will copy all the required files into the correct locations on the server
# Config goes into: /usr/local/etc/scanoss/vulnerabilities
# Logs go into: /var/log/scanoss/vulnerabilities
# Service definition goes into: /etc/systemd/system
# Binary & startup go into: /usr/local/bin
#
################################################################

show_help() {
  echo "$0 [-h|--help] [-f|--force] [environment]"
  echo "   Setup and copy the relevant files into place on a server to run the SCANOSS VULNERABILITIES API"
  echo "   [environment] allows the optional specification of a suffix to allow multiple services"
  echo "   -f | --force   Run without interactive prompts (skip questions, do not overwrite config)"
  exit 1
}

CONF_DIR=/usr/local/etc/scanoss/vulnerabilities
LOGS_DIR=/var/log/scanoss/vulnerabilities
CONF_DOWNLOAD=https://raw.githubusercontent.com/scanoss/vulnerabilities/main/config/app-config-prod.json

ENVIRONMENT=""
FORCE_INSTALL=0

export SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      ;;
    -f|--force)
      FORCE_INSTALL=1
      shift
      ;;
    *)
      ENVIRONMENT="$1"
      shift
      ;;
  esac
done

# Makes sure the scanoss user exists
export RUNTIME_USER=scanoss
if ! getent passwd $RUNTIME_USER > /dev/null ; then
  echo "Runtime user does not exist: $RUNTIME_USER"
  echo "Please create using: useradd --system $RUNTIME_USER"
  exit 1
fi
# Also, make sure we're running as root
if [ "$EUID" -ne 0 ] ; then
  echo "Please run as root"
  exit 1
fi

if [ "$FORCE_INSTALL" -eq 1 ]; then
  echo "[FORCE] Installing Vulnerabilities API $ENVIRONMENT without prompts..."
else
  read -p "Install Vulnerabilities API $ENVIRONMENT (y/n) [n]? " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Stopping."
    exit 1
  fi
fi

# Setup all the required folders and ownership
echo "Setting up Vulnerabilities API system folders..."
mkdir -p "$CONF_DIR" || { echo "mkdir failed"; exit 1; }
mkdir -p "$LOGS_DIR" || { echo "mkdir failed"; exit 1; }

if [ "$RUNTIME_USER" != "root" ] ; then
  export LOG_DIR=/var/log/scanoss
  echo "Changing ownership of $LOG_DIR to $RUNTIME_USER ..."
  chown -R $RUNTIME_USER $LOG_DIR || { echo "chown failed"; exit 1; }
fi

# Setup the service
SC_SERVICE_FILE="scanoss-vulnerabilities-api.service"
SC_SERVICE_NAME="scanoss-vulnerabilities-api"
if [ -n "$ENVIRONMENT" ] ; then
  SC_SERVICE_FILE="scanoss-vulnerabilities-api-${ENVIRONMENT}.service"
  SC_SERVICE_NAME="scanoss-vulnerabilities-api-${ENVIRONMENT}"
fi

service_stopped=""
if [ -f "/etc/systemd/system/$SC_SERVICE_FILE" ] ; then
  echo "Stopping $SC_SERVICE_NAME service first..."
  systemctl stop "$SC_SERVICE_NAME" || { echo "service stop failed"; exit 1; }
  service_stopped="true"
fi

echo "Copying service startup config..."
if [ -f "$SCRIPT_DIR/$SC_SERVICE_FILE" ] ; then
  cp "$SCRIPT_DIR/$SC_SERVICE_FILE" /etc/systemd/system || { echo "service copy failed"; exit 1; }
else 
  echo "No service file found at $SCRIPT_DIR/$SC_SERVICE_FILE"
fi

cp "$SCRIPT_DIR/scanoss-vulnerabilities-api.sh" /usr/local/bin || { echo "startup script copy failed"; exit 1; }
chmod +x /usr/local/bin/scanoss-vulnerabilities-api.sh

# Config file
CONF=app-config-prod.json
if [ -n "$ENVIRONMENT" ] ; then
  CONF="app-config-${ENVIRONMENT}.json"
fi

if [ -f "$SCRIPT_DIR/$CONF" ]; then
  if [ -f "$CONF_DIR/$CONF" ]; then
    if [ "$FORCE_INSTALL" -eq 1 ]; then
      echo "[FORCE] Config already exists at $CONF_DIR/$CONF, skipping replacement."
    else
      read -p "Config file exists. Replace $CONF_DIR/$CONF? (y/n) [n]? " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp "$SCRIPT_DIR/$CONF" "$CONF_DIR/" || { echo "config copy failed"; exit 1; }
      else
        echo "Skipping config copy."
      fi
    fi
  else
    cp "$SCRIPT_DIR/$CONF" "$CONF_DIR/" || { echo "config copy failed"; exit 1; }
  fi
else
  if [ ! -f "$CONF_DIR/$CONF" ]; then
    if [ "$FORCE_INSTALL" -eq 1 ]; then
      echo "[FORCE] Downloading default config to $CONF_DIR/$CONF"
      curl -s "$CONF_DOWNLOAD" > "$CONF_DIR/$CONF" || echo "Warning: curl download failed"
    else
      read -p "Download sample $CONF (y/n) [y]? " -n 1 -r
      echo
      if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        curl -s "$CONF_DOWNLOAD" > "$CONF_DIR/$CONF" || echo "Warning: curl download failed"
      else
        echo "Please put the config file into: $CONF_DIR/$CONF"
      fi
    fi
  fi
fi

# Copy the binary
BINARY=scanoss-vulnerabilities-api
if [ -f "$SCRIPT_DIR/$BINARY" ] ; then
  echo "Copying app binary to /usr/local/bin ..."
  cp "$SCRIPT_DIR/$BINARY" /usr/local/bin || { echo "binary copy failed"; exit 1; }
  chmod +x /usr/local/bin/$BINARY || echo "Warning: could not set executable permission on $BINARY"
else
  echo "Please copy the Vulnerabilities API binary file into: /usr/local/bin/$BINARY"
fi

echo "Installation complete."
if [ "$service_stopped" == "true" ] ; then
  echo "Restarting service after install..."
  systemctl start "$SC_SERVICE_NAME" || { echo "failed to restart service"; exit 1; }
  systemctl status "$SC_SERVICE_NAME"
fi

if [ ! -f "$CONF_DIR/$CONF" ] ; then
  echo
  echo "Warning: Please create a configuration file in: $CONF_DIR/$CONF"
  echo "A sample version can be downloaded from GitHub:"
  echo "curl $CONF_DOWNLOAD > $CONF_DIR/$CONF"
fi

echo
echo "Review service config in: $CONF_DIR/$CONF"
echo "Logs are stored in: $LOGS_DIR"
echo "Start the service using: systemctl start $SC_SERVICE_NAME"
echo "Stop the service using: systemctl stop $SC_SERVICE_NAME"
echo "Get service status using: systemctl status $SC_SERVICE_NAME"
echo "Count the number of running scans using: pgrep -P \$(pgrep -d, scanoss-vulnerabilities-api) | wc -l"
