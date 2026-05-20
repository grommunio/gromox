#!/bin/bash

SCRIPT_BUILD=2025050204

LOG_FILE="/var/log/gromox-mbox-repair-tool.log"

SOFTDELETE_TIMESTAMP=${SOFTDELETE_TIMESTAMP:-30d20h}

function TrapQuit {
        local exitcode=0

        if [ "$SCRIPT_GOOD" == true ]; then
                log "Operation finished with success after ${SECONDS} seconds"
                exitcode=0
        else
                log "Operation failed after ${SECONDS} seconds" "ERROR"
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
                (>&2 echo -e "$log_line")
        else
                echo "${log_line}"
        fi
        echo "${log_line}" >> "${LOG_FILE}"
}


function get_maildirs {
        command gromox-mbop foreach.mb.here echo-maildir
}

function cleanup {
        for maildir in $TARGET_MAILDIRS; do
                if [ ! -d "${maildir}" ]; then
                        log "Maildir ${maildir} does not exist" "ERROR"
                        continue
                fi
                if [ "$SOFTDELETE_TIMESTAMP" != "" ]; then
                        start_time=${SECONDS}
                        if [ "${_DRYRUN}" == false ]; then
                                log "Purging soft deletions for ${maildir}"
                                if command gromox-mbop -d "${maildir}" purge-softdelete -r -t "$SOFTDELETE_TIMESTAMP" IPM_SUBTREE ; then
                                        log "Operation took $((SECONDS-start_time)) seconds for $maildir"
                                else
                                        log "Failed to purge soft deletions for ${maildir}" "ERROR"
                                fi
                        else
                                log "Would soft delete mails for ${maildir}"
                        fi
                fi
                start_time=${SECONDS}
                if [ "${_DRYRUN}" == false ]; then
                        log "Purging datafiles for ${maildir}"
                        if command gromox-mbop -d "${maildir}" purge-datafiles ; then
                                log "Operation took $((SECONDS-start_time)) seconds for ${maildir}"
                        else
                                log "Failed to purge datafiles for ${maildir}" "ERROR"
                        fi
                else
                        log "Would purge datafiles for ${maildir}"

                fi
        done
}

function repair_mbox {
        log "Running mailbox checks"

        for maildir in $TARGET_MAILDIRS; do
                log "Checking maildir ${maildir}"
                if [ ! -d "${maildir}" ]; then
                        log "Maildir ${maildir} does not exist" "ERROR"
                        continue
                fi

                # gromox-mbck returns 0 regardless of mailbox state
                if command gromox-mbck "${maildir}/exmdb/exchange.sqlite3" | grep "\[0 issues\]"; then
                        log "Check successful on ${maildir}"
                elif [ "${_REPAIR_MAILBOX}" == true ]; then
                        log "Check failed for ${maildir}" "ERROR"
                        if [ "${_DRYRUN}" == false ]; then
                                log "Repairing maildir with gromox-mbck"
                                if ! command gromox-mbck -p "${maildir}/exmdb/exchange.sqlite3" ; then
                                        log "Repairing ${maildir}/exmdb/exchange.sqlite3 failed. stoppting operations" "ERROR"
                                        break
                                fi
                        else
                                log "Would repair maildir ${maildir} if not dryrun"
                        fi
                fi
        done
}

function repair_sql {
        log "Running mailbox sql checks"


        if systemctl is-active gromox-http.service > /dev/null; then
                log "gromox-http is active currently."
                gromox_http_is_active=true
        else
                log "gromox-http is inactive currently."
                gromox_http_is_active=false
        fi
        gromox_http_needs_restart=false

        for maildir in $TARGET_MAILDIRS; do
                if [ ! -d "${maildir}" ]; then
                        log "Maildir ${maildir} does not exist" "ERROR"
                        continue
                fi
                log "Checking sql database in ${maildir}/exmdb"
                # This expects sqlite to output "ok"
                if [ "$(sqlite3 -readonly "${maildir}/exmdb/exchange.sqlite3" 'pragma integrity_check;')" != "ok" ]; then
                        log "Maildir ${maildir} has errors according to sqlite3" "ERROR"
                        if [ "${_DRYRUN}" == false ] && [ "${_REPAIR_SQL}" == true ]; then
                                log "Repairing sqlite database. This will shutdown gromox-http"
                                systemctl stop gromox-http.service
                                if systemctl is-active gromox-http.service > /dev/null; then
                                        log "Cannot stop gromox-http, stopping operations" "ERROR"
                                        break
                                else
                                        if [ "${gromox_http_is_active}" == true ]; then
                                                gromox_http_needs_restart=true
                                        fi
                                        log "Trying to create a recovery database"
                                        if ! sqlite3 -readonly -cmd 'PRAGMA foreign_keys=0;' "${maildir}"/exmdb/exchange.sqlite3 '.recover' | sqlite3 "${maildir}"/exmdb/new.db ; then
                                                log "sqlite recovery of db in ${maildir} failed, stoping operations" "ERROR"
                                                break
                                        fi
                                        if ! chmod u=rw,g=rw "${maildir}/exmdb/new.db" ; then
                                                log "Failed to set permissions on ${maildir}/exmdb/new.db" "ERROR"
                                                break
                                        fi
                                        if ! chown grommunio:gromox "${maildir}/exmdb/new.db" ; then
                                                log "Failed to set ownsersihp on ${maildir}/exmdb/new.db" "ERROR"
                                                break
                                        fi
                                        if ! mv "${maildir}/exmdb/exchange.sqlite3" "${maildir}/exmdb/exchange.sqlite3.old" ; then
                                                log "Failed to move ${maildir}/exmdb/exchange.sqlite3 to ${maildir}/exmdb/sqlite3.old" "ERROR"
                                                break
                                        fi
                                        if ! mv "${maildir}/exmdb/new.db" "${maildir}/exmdb/exchange.sqlite3" ; then
                                                log "Failed to move repaired db ${maildir}/exmdb/new.db to ${maildir}/exmdb/sqlite3" "ERROR"
                                                break
                                        fi
                                        log "Finished repairing ${maildir}/exmdb/exchange.sqlite3"
                                        log "A security copy has been created as ${maildir}/exmdb/exchange.sqlite3.old"
                                fi
                        else
                                log "Would reapir sql database in ${maildir}/exmdb if not dryrun"
                        fi
                else
                        log "SQL database in ${maildir}/exmdb is okay"
                fi
        done
        if [ "${gromox_http_is_active}" == true ] && [ ${gromox_http_needs_restart} == true ]; then
                log "Restarting gromox-http"
                systemctl start gromox-http.service
        fi
}

function Usage {

        echo "$0 $PROGRAM_BUILD"
        echo ""
        echo "This script comes without any warranty, use at your own risk"
        echo "It uses various repair techniques for one or all mailboxes of a system"
        echo "These repair techniques are on the official Grommunio docs"
        echo ""
        echo "$0 options:"
        echo ""
        echo "--cleanup                Runs a clenaup on mailboxes"
        echo "--check-mbox             Checks mailboxes"
        echo "--repair-mbox            Checks and tries to repair mailboxes"
        echo "--check-sql              Checks sqlite database"
        echo "--repair-sql             Checks and tries to repair sqlite database. Will stop gromox-http temporarily"
        echo "--dryrun                 Actually don't run any modifications"
        echo "--maildir=all|path       When set to \"all\", will run over all maildirs. Can take mailbox path, eg /var/lib/gromox/user/1/2"

        exit 1
}


_DRYRUN=false
_RUN_CLEANUP=false
_CHECK_MAILBOX=false
_REPAIR_MAILBOX=false
_REPAIR_SQL=false
_TARGET_MAILDIRS=""

function GetCommandlineArguments {
        if [ $# -eq 0 ]; then
                Usage
        fi

        for i in "${@}"; do
                case "$i" in
                        --dryrun)
                        _DRYRUN=true
                        ;;
                        --cleanup)
                        _RUN_CLEANUP=true
                        ;;
                        --check-mbox)
                        _CHECK_MAILBOX=true
                        ;;
                        --repair-mbox)
                        _REPAIR_MAILBOX=true
                        ;;
                        --check-sql)
                        _CHECK_SQL=true
                        ;;
                        --repair-sql)
                        _REPAIR_SQL=true
                        ;;
                        --maildir=*)
                        TARGET_MAILDIRS="${i##*=}"
                        # Also strip trailing slashes
                        TARGET_MAILDIRS="${TARGET_MAILDIRS%/}"
                        ;;
                        *)
                        log "Unknown option '$i'" "CRITICAL"
                        Usage
                        ;;
                esac
        done
}



## ENTRY POINT

trap TrapQuit TERM EXIT HUP QUIT
set -o pipefail
set -o errtrace
SCRIPT_GOOD=true

echo "Gromox mbox repair tool v${SCRIPT_BUILD}"

GetCommandlineArguments "${@}"

if [ "${TARGET_MAILDIRS}" != "all" ]; then
        if [ ! -d "${TARGET_MAILDIRS}" ]; then
                log "No valid mailbox \"${TARGET_MAILDIRS}\" specified" "ERROR"
                exit 1
        fi
else
        TARGET_MAILDIRS="$(get_maildirs)"
fi

log "$0 invoked on $(date)"

if [ "${_CHECK_MAILBOX}" == true ] || [ "${_REPAIR_MAILBOX}" == true ]; then
        repair_mbox
fi
if [ "${_CHECK_SQL}" == true ] || [ "${_REPAIR_SQL}" == true ]; then
        repair_sql
fi
[ "${_RUN_CLEANUP}" == true ] && cleanup
