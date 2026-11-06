#!/bin/bash

echo "==============================================="
echo "      PASSWORD POLICY SECURITY AUDIT"
echo "==============================================="
echo

LOGIN_DEFS="/etc/login.defs"

if [ ! -f "$LOGIN_DEFS" ]; then
    echo "[FAIL] login.defs file not found."
    exit 1
fi

echo "Checking Maximum Password Age..."
MAX=$(grep "^PASS_MAX_DAYS" $LOGIN_DEFS | awk '{print $2}')
if [ -n "$MAX" ] && [ "$MAX" -le 90 ]; then
    echo "[PASS] PASS_MAX_DAYS = $MAX"
else
    echo "[WARNING] PASS_MAX_DAYS = $MAX"
fi

echo

echo "Checking Minimum Password Age..."
MIN=$(grep "^PASS_MIN_DAYS" $LOGIN_DEFS | awk '{print $2}')
if [ -n "$MIN" ]; then
    echo "[PASS] PASS_MIN_DAYS = $MIN"
else
    echo "[WARNING] PASS_MIN_DAYS not configured"
fi

echo

echo "Checking Password Warning Age..."
WARN=$(grep "^PASS_WARN_AGE" $LOGIN_DEFS | awk '{print $2}')
if [ -n "$WARN" ]; then
    echo "[PASS] PASS_WARN_AGE = $WARN"
else
    echo "[WARNING] PASS_WARN_AGE not configured"
fi

echo

echo "Checking Password Complexity..."

if grep -q "pam_pwquality.so" /etc/pam.d/common-password 2>/dev/null
then
    echo "[PASS] Password complexity module enabled."
else
    echo "[WARNING] pam_pwquality module not enabled."
fi

echo
echo "Password Policy Audit Completed."
