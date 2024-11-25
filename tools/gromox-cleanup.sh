#!/usr/bin/env bash

SCRIPT_BUILD=202411254

GROMOX_MAILDIR_PATH="/var/lib/gromox"
SOFTDELETE_TIMESTAMP="30d20h"

function TrapQuit {
        local exitcode=0

        if [ "$SCRIPT_GOOD" == true ]; then
                log "Cleanup operation finished with success after ${SECONDS} seconds"
                exitcode=0
        else
                log "Cleanup operation failed after ${SECONDS}" "ERROR"
                exitcode=1
        fi
        exit $exitcode
}


function log {
        local log_line="${1}"
        local level="${2}"

        if [ "${level}" != "" ]; then
                log_line="${level}: ${log_line}"
        fi

        if [ "${level}" == "ERROR" ]; then
                SCRIPT_GOOD=false
                echo "ERROR: ${log_line}" >> "${LOG_FILE}"
                (>&2 echo -e "$log_line")
        else
                echo "${log_line}" >> "${LOG_FILE}"
                echo "${log_line}"
        fi
}


function cleanup {
        for maildir in $(grommunio-admin user query maildir | awk '{if ($1~gromox_mail) {print $1}}' gromox="${GROMOX_MAILDIR_PATH}"); do
                if [ "$SOFTDELETE_TIMESTAMP" != "" ]; then
                        log "Purging soft deletions for ${maildir}"
                        start_time=${SECONDS}
                        gromox-mbop -d "${maildir}" purge-softdelete -r -t "$SOFTDELETE_TIMESTAMP" IPM_SUBTREE >> "${LOG_FILE}" 2>&1
                        if [ $? -eq 0 ]; then
                                log "Operation took $((${SECONDS}-${start_time})) for ${maildir}"
                        else
                                log "Failed to purge soft deletions for ${maildir}" "ERROR"
                        fi
                fi
                log "Purging datafiles for ${maildir}"
                start_time=${SECONDS}
                gromox-mbop -d "${maildir}" purge-datafiles >> "${LOG_FILE}" 2>&1
                if [ $? -eq 0 ]; then
                        log "Operation took $((${SECONDS}-${start_time}))  for ${maildir}"
                else
                        log "Failed to purge datafiles for ${maildir}" "ERROR"
                fi
        done
}

## ENTRY POINT

trap TrapQuit TERM EXIT HUP QUIT
set -o pipefail
set -o errtrace
SCRIPT_GOOD=true

## Default log file

SCRIPT_NAME=$(basename "$0")
if [ -w /var/log ]; then
        LOG_FILE="/var/log/${SCRIPT_NAME}.log"
elif ([ "${HOME}" != "" ] && [ -w "${HOME}" ]); then
        LOG_FILE="${HOME}/${SCRIPT_NAME}.log"
elif [ -w . ]; then
        LOG_FILE="./${SCRIPT_NAME}.log"
else
        LOG_FILE="/tmp/${SCRIPT_NAME}.log"
fi

cleanup
