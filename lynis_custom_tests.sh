    InsertSection "Custom tests - Password policy audit"

    LOGIN_DEFS="${ROOTDIR}etc/login.defs"
    PAM_COMMON="${ROOTDIR}etc/pam.d/common-password"

    if [ -f "${LOGIN_DEFS}" ]; then PREQS_MET="YES"; SKIPREASON=""; else PREQS_MET="NO"; SKIPREASON="login.defs file not found"; fi

  
    Register --test-no CUST-1010 --preqs-met ${PREQS_MET} --skip-reason "${SKIPREASON}" --weight L --network NO --category security --description "Checking maximum password age (PASS_MAX_DAYS)"
    if [ ${SKIPTEST} -eq 0 ]; then
        LogText "Test: reading PASS_MAX_DAYS from ${LOGIN_DEFS}"
        MAX=$(${GREPBINARY} "^PASS_MAX_DAYS" "${LOGIN_DEFS}" | ${AWKBINARY} '{print $2}')
        if [ -n "${MAX}" ] && [ "${MAX}" -le 90 ] 2>/dev/null; then
            LogText "Result: PASS_MAX_DAYS is ${MAX}"
            Display --indent 2 --text "- Maximum password age (PASS_MAX_DAYS = ${MAX})" --result PASS --color GREEN
        else
            LogText "Result: PASS_MAX_DAYS is ${MAX:-not set}, which is not 90 days or less"
            Display --indent 2 --text "- Maximum password age (PASS_MAX_DAYS = ${MAX:-not set})" --result WARNING --color RED
            ReportWarning "${TEST_NO}" "Maximum password age is not 90 days or less" "PASS_MAX_DAYS = ${MAX:-not set}" "text:Set PASS_MAX_DAYS to 90 or lower in /etc/login.defs"
        fi
    fi

    Register --test-no CUST-1020 --preqs-met ${PREQS_MET} --skip-reason "${SKIPREASON}" --weight L --network NO --category security --description "Checking minimum password age (PASS_MIN_DAYS)"
    if [ ${SKIPTEST} -eq 0 ]; then
        LogText "Test: reading PASS_MIN_DAYS from ${LOGIN_DEFS}"
        MIN=$(${GREPBINARY} "^PASS_MIN_DAYS" "${LOGIN_DEFS}" | ${AWKBINARY} '{print $2}')
        if [ -n "${MIN}" ]; then
            LogText "Result: PASS_MIN_DAYS is ${MIN}"
            Display --indent 2 --text "- Minimum password age (PASS_MIN_DAYS = ${MIN})" --result PASS --color GREEN
        else
            LogText "Result: PASS_MIN_DAYS is not configured"
            Display --indent 2 --text "- Minimum password age (PASS_MIN_DAYS not set)" --result WARNING --color RED
            ReportWarning "${TEST_NO}" "Minimum password age is not configured" "PASS_MIN_DAYS" "text:Set PASS_MIN_DAYS in /etc/login.defs"
        fi
    fi

    Register --test-no CUST-1030 --preqs-met ${PREQS_MET} --skip-reason "${SKIPREASON}" --weight L --network NO --category security --description "Checking password warning age (PASS_WARN_AGE)"
    if [ ${SKIPTEST} -eq 0 ]; then
        LogText "Test: reading PASS_WARN_AGE from ${LOGIN_DEFS}"
        WARN=$(${GREPBINARY} "^PASS_WARN_AGE" "${LOGIN_DEFS}" | ${AWKBINARY} '{print $2}')
        if [ -n "${WARN}" ]; then
            LogText "Result: PASS_WARN_AGE is ${WARN}"
            Display --indent 2 --text "- Password warning age (PASS_WARN_AGE = ${WARN})" --result PASS --color GREEN
        else
            LogText "Result: PASS_WARN_AGE is not configured"
            Display --indent 2 --text "- Password warning age (PASS_WARN_AGE not set)" --result WARNING --color RED
            ReportWarning "${TEST_NO}" "Password warning age is not configured" "PASS_WARN_AGE" "text:Set PASS_WARN_AGE in /etc/login.defs"
        fi
    fi

    if [ -f "${PAM_COMMON}" ]; then PAM_PREQS="YES"; PAM_SKIP=""; else PAM_PREQS="NO"; PAM_SKIP="common-password not found (Debian and Ubuntu only)"; fi
    Register --test-no CUST-1040 --preqs-met ${PAM_PREQS} --skip-reason "${PAM_SKIP}" --weight L --network NO --category security --description "Checking password complexity module (pam_pwquality)"
    if [ ${SKIPTEST} -eq 0 ]; then
        LogText "Test: looking for pam_pwquality.so in ${PAM_COMMON}"
        if ${GREPBINARY} -q "pam_pwquality.so" "${PAM_COMMON}" 2>/dev/null; then
            LogText "Result: pam_pwquality is enabled"
            Display --indent 2 --text "- Password complexity module (pam_pwquality)" --result PASS --color GREEN
        else
            LogText "Result: pam_pwquality is not enabled"
            Display --indent 2 --text "- Password complexity module (pam_pwquality)" --result WARNING --color RED
            ReportWarning "${TEST_NO}" "pam_pwquality module is not enabled" "${PAM_COMMON}" "text:Install libpam-pwquality and enable it in common-password"
        fi
    fi

    WaitForKeyPress



    InsertSection "Custom tests - SSH security configuration audit"

    SSH_CONFIG="${ROOTDIR}etc/ssh/sshd_config"

    if [ -f "${SSH_CONFIG}" ]; then SSH_PREQS="YES"; SSH_SKIP=""; else SSH_PREQS="NO"; SSH_SKIP="sshd_config file not found (is the SSH server installed?)"; fi

    # Test        : CUST-2010
    # Description : Root login over SSH should be disabled
    Register --test-no CUST-2010 --preqs-met ${SSH_PREQS} --skip-reason "${SSH_SKIP}" --weight M --network NO --category security --description "Checking SSH root login (PermitRootLogin)"
    if [ ${SKIPTEST} -eq 0 ]; then
        LogText "Test: reading PermitRootLogin from ${SSH_CONFIG}"
        ROOT=$(${GREPBINARY} "^PermitRootLogin" "${SSH_CONFIG}" | ${AWKBINARY} '{print $2}')
        if [ "${ROOT}" = "no" ]; then
            LogText "Result: root login is disabled"
            Display --indent 2 --text "- Root login (PermitRootLogin = no)" --result PASS --color GREEN
        else
            LogText "Result: PermitRootLogin is ${ROOT:-not set}"
            Display --indent 2 --text "- Root login (PermitRootLogin = ${ROOT:-not set})" --result WARNING --color RED
            ReportWarning "${TEST_NO}" "SSH root login is not set to no" "PermitRootLogin = ${ROOT:-not set}" "text:Set PermitRootLogin no in /etc/ssh/sshd_config"
        fi
    fi

    Register --test-no CUST-2020 --preqs-met ${SSH_PREQS} --skip-reason "${SSH_SKIP}" --weight L --network NO --category security --description "Checking SSH password authentication (PasswordAuthentication)"
    if [ ${SKIPTEST} -eq 0 ]; then
        LogText "Test: reading PasswordAuthentication from ${SSH_CONFIG}"
        PASSAUTH=$(${GREPBINARY} "^PasswordAuthentication" "${SSH_CONFIG}" | ${AWKBINARY} '{print $2}')
        if [ "${PASSAUTH}" = "no" ]; then
            LogText "Result: password authentication is disabled"
            Display --indent 2 --text "- Password authentication (PasswordAuthentication = no)" --result PASS --color GREEN
        else
            LogText "Result: PasswordAuthentication is ${PASSAUTH:-not set}"
            Display --indent 2 --text "- Password authentication (PasswordAuthentication = ${PASSAUTH:-not set})" --result INFO --color YELLOW
        fi
    fi

    Register --test-no CUST-2030 --preqs-met ${SSH_PREQS} --skip-reason "${SSH_SKIP}" --weight M --network NO --category security --description "Checking SSH empty passwords (PermitEmptyPasswords)"
    if [ ${SKIPTEST} -eq 0 ]; then
        LogText "Test: reading PermitEmptyPasswords from ${SSH_CONFIG}"
        EMPTY=$(${GREPBINARY} "^PermitEmptyPasswords" "${SSH_CONFIG}" | ${AWKBINARY} '{print $2}')
        if [ "${EMPTY}" = "no" ]; then
            LogText "Result: empty passwords are disabled"
            Display --indent 2 --text "- Empty passwords (PermitEmptyPasswords = no)" --result PASS --color GREEN
        else
            LogText "Result: PermitEmptyPasswords is ${EMPTY:-not set}"
            Display --indent 2 --text "- Empty passwords (PermitEmptyPasswords = ${EMPTY:-not set})" --result WARNING --color RED
            ReportWarning "${TEST_NO}" "SSH may allow empty passwords" "PermitEmptyPasswords = ${EMPTY:-not set}" "text:Set PermitEmptyPasswords no in /etc/ssh/sshd_config"
        fi
    fi

    Register --test-no CUST-2040 --preqs-met ${SSH_PREQS} --skip-reason "${SSH_SKIP}" --weight L --network NO --category security --description "Checking SSH maximum authentication attempts (MaxAuthTries)"
    if [ ${SKIPTEST} -eq 0 ]; then
        LogText "Test: reading MaxAuthTries from ${SSH_CONFIG}"
        TRIES=$(${GREPBINARY} "^MaxAuthTries" "${SSH_CONFIG}" | ${AWKBINARY} '{print $2}')
        if [ -n "${TRIES}" ]; then
            LogText "Result: MaxAuthTries is ${TRIES}"
            Display --indent 2 --text "- Maximum login attempts (MaxAuthTries = ${TRIES})" --result PASS --color GREEN
        else
            LogText "Result: MaxAuthTries is not set, the default value is used"
            Display --indent 2 --text "- Maximum login attempts (MaxAuthTries not set)" --result INFO --color YELLOW
        fi
    fi

    Register --test-no CUST-2050 --preqs-met ${SSH_PREQS} --skip-reason "${SSH_SKIP}" --weight L --network NO --category security --description "Checking SSH login grace time (LoginGraceTime)"
    if [ ${SKIPTEST} -eq 0 ]; then
        LogText "Test: reading LoginGraceTime from ${SSH_CONFIG}"
        GRACE=$(${GREPBINARY} "^LoginGraceTime" "${SSH_CONFIG}" | ${AWKBINARY} '{print $2}')
        if [ -n "${GRACE}" ]; then
            LogText "Result: LoginGraceTime is ${GRACE}"
            Display --indent 2 --text "- Login grace time (LoginGraceTime = ${GRACE})" --result PASS --color GREEN
        else
            LogText "Result: LoginGraceTime is not set, the default value is used"
            Display --indent 2 --text "- Login grace time (LoginGraceTime not set)" --result INFO --color YELLOW
        fi
    fi

WaitForKeyPress

#
#================================================================================
# Custom tests for Lynis - https://cisofy.com/lynis/
