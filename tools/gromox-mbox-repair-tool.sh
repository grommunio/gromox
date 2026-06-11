#!/bin/bash

shopt -s extglob

SCRIPT_BUILD=2026061102

LOG_FILE="/var/log/gromox-mbox-repair-tool.log"

SOFTDELETE_TIMESTAMP=${SOFTDELETE_TIMESTAMP:-30d20h}

TrapQuit() {
        local exitcode=0

        if [ "$SCRIPT_GOOD" = true ]; then
                log "Operation finished with success after ${SECONDS} seconds"
                exitcode=0
        else
                log "Operation failed after ${SECONDS} seconds" "ERROR"
                exitcode=1
        fi
        exit $exitcode
}


log() {
        local log_line="${1}"
        local level="${2}"

        if [ "${level}" != "" ]; then
                log_line="${level}: ${log_line}"
        fi

        if [ "${level}" = "ERROR" ]; then
                SCRIPT_GOOD=false
                (>&2 echo -e "$log_line")
        else
                echo "${log_line}"
        fi
        echo "${log_line}" >> "${LOG_FILE}"
}

log_quit() {
        log "${1}" "${2}"
        exit 1
}

get_maildirs() {
        local username="${1:-false}"

        if [ "${username}" != false ]; then
            command gromox-mbop -u "${username}" echo-maildir
        else
            command gromox-mbop foreach.mb.here echo-maildir
        fi
}

get_username_from_maildir() {
        local maildir="${1}"

        command grommunio-admin user query username -f maildir="${maildir}"
}

user_has_pop3_imap() {
        local username="${1}"

        has_pop3_imap="$(command grommunio-admin user query username --filter pop3_imap=True --filter username="${username}")"
        if [ "${has_pop3_imap}" = "${username}" ]; then
                echo true
        else
                echo false
        fi
}

cleanup() {
        for maildir in $TARGET_MAILDIRS; do
                if [ ! -d "${maildir}" ]; then
                        log "Maildir ${maildir} does not exist" "ERROR"
                        continue
                fi
                if [ "$SOFTDELETE_TIMESTAMP" != "" ]; then
                        start_time=${SECONDS}
                        if [ "${_DRYRUN}" = false ]; then
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
                if [ "${_DRYRUN}" = false ]; then
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

repair_mbox() {
        log "Running mailbox checks"

        for maildir in $TARGET_MAILDIRS; do
                log "Checking maildir ${maildir}"
                if [ ! -d "${maildir}" ]; then
                        log "Maildir ${maildir} does not exist" "ERROR"
                        continue
                fi

                # gromox-mbck returns 0 regardless of mailbox state
                result="$(command gromox-mbck "${maildir}/exmdb/exchange.sqlite3")"
                if echo "$result" | grep "\[0 issues\]" >/dev/null 2>&1; then
                    log "Check successful on ${maildir}"
                else
                    log "Result: $result"
                    if [ "${_REPAIR_MAILBOX}" = true ]; then
                        if [ "${_DRYRUN}" = false ]; then
                                log "Repairing maildir with gromox-mbck"
                                if ! command gromox-mbck -p "${maildir}/exmdb/exchange.sqlite3" ; then
                                        log "Repairing ${maildir}/exmdb/exchange.sqlite3 failed. stoppting operations" "ERROR"
                                        break
                                else
                                        log "Finished repairing maildir ${maildir}/exmdb/exchange.sqlite3"
                                fi
                        else
                                log "Would repair maildir ${maildir} if not dryrun"
                        fi
                    else
                            log "Check failed for ${maildir}" "ERROR"
                    fi
                fi
        done
}

repair_sql() {
        log "Running mailbox sql checks"

        # Simulate bash arrays
        readonly gromox_http_service=0
        readonly grommunio_index_service=1
        services_to_monitor=(gromox-http.service grommunio-index.service)
        service_is_active=()
        for service in "${services_to_monitor[@]}"; do
                if systemctl is-active "${service}" > /dev/null; then
                        log "${service} is active currently."
                        service_is_active[${service//[.-]/_}]=true
                else
                        log "${service} is inactive currently."
                        service_is_active[${service//[.-]/_}]=true
                fi
        done

        services_need_to_restart=false
        do_repairs=false
        for maildir in $TARGET_MAILDIRS; do
                if [ ! -d "${maildir}" ]; then
                        log "Maildir ${maildir} does not exist" "ERROR"
                        continue
                fi
                log "Checking sql database in ${maildir}/exmdb"
                # This expects sqlite to output "ok"
                if [ "$(sqlite3 -readonly "${maildir}/exmdb/exchange.sqlite3" 'pragma integrity_check;')" != "ok" ]; then
                        if [ "${_DRYRUN}" = false ] && [ "${_REPAIR_SQL}" = true ]; then
                                if [ "${do_repairs}" = false ]; then
                                        log "Repairing sqlite database. This will shutdown ${services_to_monitor[*]}"
                                        do_repairs=true
                                        services_need_to_restart=true
                                        for service in "${services_to_monitor[@]}"; do
                                                log "Stopping service ${service}"
                                                systemctl stop "${service}"
                                                if systemctl is-active "${service}" > /dev/null; then
                                                        log "Cannot stop ${service}, stopping operations" "ERROR"
                                                        do_repairs=false
                                                fi
                                        done
                                fi
                                if [ "${do_repairs}" = true ]; then
                                        log "Trying to create a recovery database"
                                        continue
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
                                else
                                        log "No repairs were attempted"
                                fi
                        else
                                if [ "${_DRYRUN}" = false ]; then
                                        log "Maildir ${maildir} has errors according to sqlite3" "ERROR"
                                else
                                        log "Would repair sql database in ${maildir}/exmdb if not dryrun"
                                fi
                        fi
                else
                        log "SQL database in ${maildir}/exmdb is okay"
                fi
        done

        if [ "${services_need_to_restart}" = true ]; then
                for service in "${services_to_monitor[@]}"; do
                        if [ "${service_is_active[${service//[.-]/_}]}" = true ]; then
                                log "Restarting ${service}"
                                systemctl start "${service}" || log "Cannot start ${service}" "ERROR"
                        fi
                done
        fi
}

repair_midb() {
        log "Running mailbox midb operations"

        # Simulate bash arrays
        readonly gromox_midb_service=0
        readonly gromox_imap_service=1
        readonly gromox_pop3_service=2
        services_to_monitor=(gromox-midb.service gromox-imap.service gromox-pop3.service)
        service_is_active=()
        for service in "${services_to_monitor[@]}"; do
                if systemctl is-active "${service}" > /dev/null; then
                        log "${service} is active currently."
                        service_is_active[${service//[.-]/_}]=true
                else
                        log "${service} is inactive currently."
                        service_is_active[${service//[.-]/_}]=true
                fi
        done

        services_need_to_restart=false
        do_repairs=false
        for maildir in $TARGET_MAILDIRS; do
                if [ ! -d "${maildir}" ]; then
                        log "Maildir ${maildir} does not exist" "ERROR"
                        continue
                else
                        username="$(get_username_from_maildir "${maildir}")"
                        if [ -z "${username}" ]; then
                                log "Username not found for ${maildir}"
                                continue
                        fi
                fi
                if [ "${_CHECK_MIDB}" = true ] || [ "${_REPAIR_MIDB}" = true ]; then
                        log "Checking midb sql database for user ${username}"
                        # gromox-mkmidb --integrity {username} returns 0 on success and 1 if integrity is not good
                        gromox-mkmidb --integrity "${username}" > /dev/null 2>&1
                elif [ "${_PURGE_MIDB}" = true ]; then
                        false
                fi
                if [ $? -ne 0 ]; then
                        if [ "${_DRYRUN}" = false ] && ([ "${_REPAIR_MIDB}" = true ] || [ "${_PURGE_MIDB}" = true ]); then
                                if [ "${do_repairs}" = false ]; then
                                        log "Regenerating midb database(s). This will shutdown ${services_to_monitor[*]}"
                                        do_repairs=true
                                        services_need_to_restart=true
                                        for service in "${services_to_monitor[@]}"; do
                                                log "Stopping service ${service}"
                                                systemctl stop "${service}"
                                                if systemctl is-active "${service}" > /dev/null; then
                                                        log "Cannot stop ${service}, stopping operations" "ERROR"
                                                        do_repairs=false
                                                fi
                                        done
                                fi
                                if [ "${do_repairs}" = true ]; then
                                        user_has_pop3_imap="$(user_has_pop3_imap "${username}")"
                                        if [ "${_REPAIR_MIDB}" = true ] || [ "${_PURGE_MIDB_UNSAFE}" = true ] || ([ "${_PURGE_MIDB_UNSAFE}" != true ] && [ "${user_has_pop3_imap}" = "true" ]); then
                                                log "Regenerating midb database for ${username}"
                                                gromox-mkmidb -fv "${username}"
                                                if [ $? -eq 0 ]; then
                                                        log "A new and empty midb database has been created. Cleaning unreferenced files now"
                                                        command gromox-mbop -u "${username}" purge-datafiles
                                                        if [ "${user_has_pop3_imap}" = "true" ] && [ "${_PURGE_MIDB_UNSAFE}" = false ]; then
                                                                log "User has pop3 and imap enabled. On next user pop3/imap connection, midb will sync data, which is IO intensive" "WARNING"
                                                        fi
                                                else
                                                        log "Midb regeneration command failed" "ERROR"
                                                fi
                                        else
                                                log "Skipping midb regeneration for user ${username} (has pop3/imap ${user_has_pop3_imap})"
                                        fi
                                else
                                        log "No repairs were attempted"
                                fi
                        else
                                if [ "${_DRYRUN}" = false ]; then
                                        log "Maildir ${maildir} has errors according to gromox-mkmidb check" "ERROR"
                                else
                                        log "Would repair midb database in ${maildir}/exmdb if not dryrun"
                                fi
                        fi
                else
                        log "Midb database in ${maildir}/exmdb is okay"
                fi
        done

        if [ "${services_need_to_restart}" = true ]; then
                for service in "${services_to_monitor[@]}"; do
                        if [ "${service_is_active[${service//[.-]/_}]}" = true ]; then
                                log "Restarting ${service}"
                                systemctl start "${service}" || log "Cannot start ${service}" "ERROR"
                        fi
                done
        fi
}

Usage() {

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
        echo "--check-midb             Checks midb sqlite database"
        echo "--repair-midb            Checks and tries to regenerate midb sqlite database. Will stop gromox-midb, imap and pop3 temporarily"
        echo "--purge-midb-safe        Removes all pop3/imap data from mailboxes that don't have pop3/imap access enabled"
        echo "--purge-midb-unsafe      Removes all pop3/imap data. The data will be regenerated on next user connection. This process is very io intensive"
        echo "--dryrun                 Actually don't run any modifications"
        echo "--maildir=all|[path]     Specify which maildir to run for, takes mailbox path, eg /var/lib/gromox/user/1/2 or \"all\""
        echo "--username=[username]    Spcify a single username for which to run the repair script, overrides --maildir"

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
                        --check-midb)
                        _CHECK_MIDB=true
                        ;;
                        --repair-midb)
                        _REPAIR_MIDB=true
                        ;;
                        --purge-midb-safe)
                        _PURGE_MIDB=true
                        _PURGE_MIDB_UNSAFE=false
                        ;;
                        --purge-midb-unsafe)
                        _PURGE_MIDB=true
                        _PURGE_MIDB_UNSAFE=true
                        ;;
                        --maildir=*)
                        TARGET_MAILDIRS="${i##*=}"
                        # Also strip trailing slashes
                        TARGET_MAILDIRS="${TARGET_MAILDIRS%/}"
                        ;;
                        --username=*)
                        USERNAME="${i##*=}"
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

GetCommandlineArguments "${@}"

if [ "${TARGET_MAILDIRS}" = "" ] && [ "${USERNAME}" = "" ]; then
        log "Script needs either valid mailbox or username" "CRITICAL"
        exit 1
fi
if [ "${USERNAME}" != "" ]; then
    TARGET_MAILDIRS="$(get_maildirs "${USERNAME}")"
    [ $? -ne 0 ] && log_quit "Cannot get maildir for user ${username}" "ERROR"
elif [ "${TARGET_MAILDIRS}" != "all" ]; then
    if [ ! -d "${TARGET_MAILDIRS}" ]; then
        log "No valid mailbox \"${TARGET_MAILDIRS}\" specified" "ERROR"
        exit 1
    fi
else
    TARGET_MAILDIRS="$(get_maildirs)"
    [ $? -ne 0 ] && log_quit "Cannot get maildirs" "ERROR"
fi


log "$0 $SCRIPT_BUILD invoked on $(date)"

if [ "${_CHECK_MAILBOX}" = true ] || [ "${_REPAIR_MAILBOX}" = true ]; then
        repair_mbox
fi
if [ "${_CHECK_SQL}" = true ] || [ "${_REPAIR_SQL}" = true ]; then
        repair_sql
fi
if [ "${_CHECK_MIDB}" = true ] || [ "${_REPAIR_MIDB}" = true ] || [ "${_PURGE_MIDB}" ]; then
        repair_midb
fi
[ "${_RUN_CLEANUP}" = true ] && cleanup
