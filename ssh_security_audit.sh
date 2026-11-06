#!/bin/bash

echo "==============================================="
echo "     SSH SECURITY CONFIGURATION AUDIT"
echo "==============================================="
echo

CONFIG="/etc/ssh/sshd_config"

if [ ! -f "$CONFIG" ]; then
    echo "[FAIL] SSH configuration file not found."
    exit 1
fi

echo "Checking Root Login..."

ROOT=$(grep "^PermitRootLogin" $CONFIG | awk '{print $2}')

if [ "$ROOT" = "no" ]; then
    echo "[PASS] Root login is disabled."
else
    echo "[WARNING] Root login setting: $ROOT"
fi

echo

echo "Checking Password Authentication..."

PASSAUTH=$(grep "^PasswordAuthentication" $CONFIG | awk '{print $2}')

if [ "$PASSAUTH" = "no" ]; then
    echo "[PASS] Password authentication disabled."
else
    echo "[INFO] Password authentication: $PASSAUTH"
fi

echo

echo "Checking Empty Passwords..."

EMPTY=$(grep "^PermitEmptyPasswords" $CONFIG | awk '{print $2}')

if [ "$EMPTY" = "no" ]; then
    echo "[PASS] Empty passwords disabled."
else
    echo "[WARNING] Empty passwords allowed."
fi

echo

echo "Checking Maximum Authentication Attempts..."

TRIES=$(grep "^MaxAuthTries" $CONFIG | awk '{print $2}')

if [ -n "$TRIES" ]; then
    echo "[PASS] MaxAuthTries = $TRIES"
else
    echo "[INFO] Using default value."
fi

echo

echo "Checking Login Grace Time..."

GRACE=$(grep "^LoginGraceTime" $CONFIG | awk '{print $2}')

if [ -n "$GRACE" ]; then
    echo "[PASS] LoginGraceTime = $GRACE"
else
    echo "[INFO] Using default value."
fi

echo
echo "SSH Security Audit Completed."
