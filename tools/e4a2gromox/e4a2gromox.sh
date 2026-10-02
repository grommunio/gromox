#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 grommunio GmbH
#
# e4a2gromox.sh - migrate mailboxes from an exchange4all (e4a) system
# (Kopano "kopano.cloud" / Kopanion appliance) to gromox.
#
# e4a stores are gromox-format private stores at a pre-grommunio schema
# level, so the migration is file based: the store directory is copied,
# gromox upgrades the sqlite schema, and a few identity fixups (ACL
# principals, EX addresses) are applied offline. See README.rst.
#
# Usage: e4a2gromox.sh [-c conf] [-o addr]... [-n] [-f] <command> [args]
#   inventory         pull domains/users/lists/store statistics from the
#                     source
#   plan              write WORKDIR/plan.tsv (review/edit before going on)
#   provision         create domains, users, aliases, lists on this host
#   transfer          pre-sync the stores while e4a is still running
#   transfer --final  consistent sync after e4a has been stopped (carries
#                     the sqlite WAL along); required before fixup
#   fixup             pre-flight, ACL rename, EX->SMTP rewrite, schema
#                     upgrade, quota re-sync
#   verify            compare folder/message counts source vs target
#  
# Options: -c FILE  config file (default ./e4a2gromox.conf,
#                   /etc/e4a2gromox.conf)
#          -o ADDR  only this source mailbox/list/alias (repeatable)
#          -n       dry run (print commands, write nothing)
#          -f       force: overwrite an existing plan.tsv / replace a
#                   target mailbox that this tool did not create / fixup
#                   without a recorded final sync

set -euo pipefail
shopt -s nullglob

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
CONF=""
DRYRUN=0
FORCE=0
declare -a ONLY=()

while getopts "c:o:nfh" opt; do
	case $opt in
	c) CONF=$OPTARG ;;
	o) ONLY+=("$OPTARG") ;;
	n) DRYRUN=1 ;;
	f) FORCE=1 ;;
	h) sed -n '/^# Usage/,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) exit 2 ;;
	esac
done
shift $((OPTIND - 1))
CMD=${1:-}
[[ -n $CMD ]] || { echo "e4a2gromox: command missing (try -h)" >&2; exit 2; }
shift
FINAL=0
for a in "$@"; do
	case $a in
	--final) FINAL=1 ;;
	*) echo "e4a2gromox: unknown argument $a" >&2; exit 2 ;;
	esac
done

if [[ -z $CONF ]]; then
	for f in ./e4a2gromox.conf /etc/e4a2gromox.conf; do
		[[ -f $f ]] && { CONF=$f; break; }
	done
fi
[[ -n $CONF && -f $CONF ]] ||
	{ echo "e4a2gromox: no config file (-c)" >&2; exit 2; }
# shellcheck source=e4a2gromox.conf.example
source "$CONF"
: "${WORKDIR:=/var/lib/e4a2gromox}" "${GROMOX_USER:=gromox}"
: "${GROMOX_GROUP:=gromox}" "${QUOTA_MODE:=source}" "${PASSWORD_MODE:=copy}"
: "${DEFAULT_LANG:=en_US}" "${DEFAULT_TZ:=UTC}" "${SRC_SSH_OPTS:=}"
: "${RSYNC_OPTS:=-aHS --info=progress2 --partial}" "${SRC_MODE:=rsync}"
: "${SRC_X500_ORG:=My Organization}" "${USER_PRIVS:=}" "${SRC_CONTAINER:=}"
: "${SRC_ARCHIVE_DIR:=$WORKDIR/archives}" "${SKIP_SOURCE_CHECK:=0}"
INV=$WORKDIR/inventory.json
PLAN=$WORKDIR/plan.tsv
CRED=$WORKDIR/credentials.txt
EXMAP=$WORKDIR/exaddr-map.json
LOG=$WORKDIR/e4a2gromox.log
PROVISIONED=$WORKDIR/provisioned.lst
TRANSFERRED=$WORKDIR/transferred.lst
FIXEDUP=$WORKDIR/fixedup.lst
mkdir -p "$WORKDIR" && chmod 700 "$WORKDIR"
FAILS=0

# ------------------------------------------------------------------ helpers
log() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }
die() { log "FATAL: $*"; exit 1; }
run() { # run a command, or print it under -n
	if [[ $DRYRUN -eq 1 ]]; then
		{ printf '+'; printf ' %q' "$@"; echo; } >&2
	else
		log "+ $*"
		"$@"
	fi
}
try_run() { # like run; a failure is logged and counted, never fatal
	TRY_OK=1
	if run "$@"; then return 0; fi
	TRY_OK=0; FAILS=$((FAILS + 1)); log "FAILED: $*"; return 0
}
note() { # note <file> <line>: append bookkeeping unless dry run
	[[ $DRYRUN -eq 1 ]] || echo "$2" >>"$1"
}
listed() { [[ -f $1 ]] && grep -qxF -- "$2" "$1"; }
src_ssh() { # run a command on the e4a host
	# shellcheck disable=SC2086
	ssh $SRC_SSH_OPTS -o BatchMode=yes "$SRC_SSH" "$@"
}
need() { command -v "$1" >/dev/null || die "missing program: $1"; }
is_only() { # is_only <addr>...: does -o restrict us away from all of them?
	[[ ${#ONLY[@]} -eq 0 ]] && return 0
	local o a
	for o in "${ONLY[@]}"; do
		for a in "$@"; do [[ $o == "$a" ]] && return 0; done
	done
	return 1
}
map_domain() { # map_domain <domain> -> mapped domain
	local d=$1 e
	for e in "${DOMAIN_MAP[@]}"; do
		[[ ${e%%=*} == "$d" ]] && { echo "${e#*=}"; return; }
	done
	echo "$d"
}
map_addr() { echo "${1%@*}@$(map_domain "${1#*@}")"; }
dm_args() { # DOMAIN_MAP as --domain-map arguments
	local e
	for e in "${DOMAIN_MAP[@]}"; do printf -- '--domain-map\n%s\n' "$e"; done
}
plan_rows() { # plan_rows <kind> -> rows of that kind ('|' separated)
	grep -v '^#' "$PLAN" | awk -F'|' -v k="$1" '$1 == k'
}
is_target_domain() { # a domain this plan creates on the target?
	[[ -f $PLAN ]] && plan_rows domain | awk -F'|' '{print $3}' | grep -qx "$1"
}
sql() { # sql <statement> -> rows (tab separated, no header)
	mysql -N grommunio -e "$1" 2>>"$LOG"
}
sql_lit() { # sql_lit <string> -> single-quoted SQL literal
	local s=${1//\\/\\\\}; s=${s//\'/\'\'}; printf "'%s'" "$s"
}
target_maildir() { sql "SELECT maildir FROM users WHERE username=$(sql_lit "$1")"; }
target_homedir() { sql "SELECT homedir FROM domains WHERE domainname=$(sql_lit "$1")"; }
principal_exists() { # user, alias or list with that address on the target?
	[[ -n $(sql "SELECT 1 FROM users WHERE username=$(sql_lit "$1") UNION
		SELECT 1 FROM aliases WHERE aliasname=$(sql_lit "$1") UNION
		SELECT 1 FROM mlists WHERE listname=$(sql_lit "$1")") ]]
}
opt_get() { # opt_get <opts-string> <key> -> value
	local kv; local IFS=';'
	for kv in $1; do [[ ${kv%%=*} == "$2" ]] && { echo "${kv#*=}"; return; }; done
	echo ""
}
gen_password() { openssl rand -base64 27 | tr -d '/+=' | cut -c1-24; }
store_stat() { # store_stat <source store path> <key> -> value from inventory
	python3 -c 'import json, sys
s = json.load(open(sys.argv[1])).get("stores", {}).get(sys.argv[2], {})
v = s.get(sys.argv[3], ""); print(v if v is not None else "")' "$INV" "$1" "$2"
}
# read one plan row into the usual variables
read_row() { IFS='|' read -r kind src dst store quota lang tz name extra opts; }

# ---------------------------------------------------------------- inventory
cmd_inventory() {
	need ssh; need python3
	[[ $DRYRUN -eq 1 ]] && { log "inventory: would query $SRC_SSH"; return; }
	log "inventory: querying $SRC_SSH"
	local tmp=$INV.tmp pwopt=""
	[[ $PASSWORD_MODE == copy ]] && pwopt="--with-passwords"
	src_ssh "python3 - $pwopt --container '$SRC_CONTAINER' --db '$SRC_DB' \
		--container-prefix '$SRC_CONTAINER_PREFIX' \
		--host-prefix '$SRC_HOST_PREFIX'" <"$HERE/e4a_inventory.py" >"$tmp"
	python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$tmp"
	mv "$tmp" "$INV"
	chmod 600 "$INV"
	python3 - "$INV" <<'PY'
import json, sys
inv = json.load(open(sys.argv[1]))
st = inv.get("stores", {})
print("domains: %d  users: %d  aliases: %d  mlists: %d  stores: %d"
      " (%d GiB cid, %d GiB sqlite)  orphan stores: %d  stores with WAL: %d" % (
      len(inv["domains"]), len(inv["users"]), len(inv["aliases"]),
      len(inv["mlists"]), len(st),
      sum(s.get("cid_mb", 0) for s in st.values()) // 1024,
      sum(s.get("sqlite_bytes", 0) for s in st.values()) >> 30,
      len(inv.get("orphan_stores", [])),
      sum(1 for s in st.values() if s.get("wal_bytes"))))
PY
	log "inventory written to $INV"
}

# --------------------------------------------------------------------- plan
cmd_plan() {
	[[ -f $INV ]] || die "run 'inventory' first"
	need python3
	if [[ -f $PLAN && $FORCE -eq 0 ]]; then
		die "$PLAN exists; edit it, or use -f to regenerate it"
	fi
	[[ $DRYRUN -eq 1 ]] && { log "plan: would write $PLAN"; return; }
	log "plan: writing $PLAN"
	python3 - "$INV" "$PLAN.tmp" "$DEFAULT_LANG" "$DEFAULT_TZ" "$QUOTA_MODE" \
		"$(printf '%s\n' "${DOMAIN_MAP[@]}")" \
		"$(printf '%s\n' "${SKIP_DOMAINS[@]}")" \
		"$(printf '%s\n' "${SKIP_USERS[@]}")" \
		"$(printf '%s\n' "${SHARED_MAILBOXES[@]}")" <<'PY'
import json, sys
inv = json.load(open(sys.argv[1]))
out = open(sys.argv[2], "w")
dlang, dtz, qmode = sys.argv[3], sys.argv[4], sys.argv[5]
dmap = dict(l.split("=", 1) for l in sys.argv[6].split("\n") if "=" in l)
skipd = set(l for l in sys.argv[7].split("\n") if l)
skipu = set(l for l in sys.argv[8].split("\n") if l)
shared = set(l for l in sys.argv[9].split("\n") if l)
def md(d): return dmap.get(d, d)
def ma(a): lp, d = a.rsplit("@", 1); return "%s@%s" % (lp, md(d))
# e4a "de-de" -> grommunio storelangs key "de_DE"
def lang(l): p = (l or "").replace("-", "_").split("_"); return (p[0].lower() + ("_" + p[1].upper() if len(p) > 1 else "")) if l else dlang
def row(*f): out.write("|".join(str(x if x is not None else "").replace("|", "/") for x in f) + "\n")
out.write("# kind|source|target|source_store|quota_mb|lang|tz|displayname|extra|opts\n")
out.write("# kinds: domain user shared alias mlist domainstore; delete or\n")
out.write("# comment out lines you do not want; 'extra' = alias target /\n")
out.write("# list members (comma separated) / domain of a domainstore;\n")
out.write("# 'opts' = key=value;... (priv=<e4a privilege_bits>, status=<e4a\n")
out.write("# address_status>, pwhash=<crypt hash>, main=<source main user of an\n")
out.write("# alias>, ltype=<list_type>, lpriv=<list privilege>, senders=<a,b>)\n")
lpriv = {0: "all", 1: "internal", 2: "domain", 3: "specific", 4: "outgoing"}
senders = {}
for sdr in inv.get("list_senders", []):
    senders.setdefault(str(sdr["list_id"]), []).append(ma(sdr["username"]))
lists_by_name = {m["listname"]: m for m in inv["mlists"]}
alias_names = set(a["aliasname"] for a in inv["aliases"])
doms = {int(d["id"]): d for d in inv["domains"]}
for d in inv["domains"]:
    if d["domainname"] in skipd: continue
    row("domain", d["domainname"], md(d["domainname"]), d["homedir_host"],
        d["max_size"], "", "", d["title"] or "", "", "srcdom=%s" % d["id"])
    st = inv.get("stores", {}).get(d["homedir_host"], {})
    if st.get("messages", 0) > 0 or len(st.get("ipm_folders", [])) > 0:
        row("domainstore", d["domainname"], md(d["domainname"]),
            d["homedir_host"], "", "", "", "", md(d["domainname"]), "srcdom=%s" % d["id"])
by_store = {}
for u in inv["users"]:
    if u["address_type"] == 0 and u["maildir_host"]:
        by_store.setdefault(u["maildir_host"], u)
for u in sorted(inv["users"], key=lambda u: (u["address_type"], u["id"])):
    dom = doms.get(u["domain_id"], {}).get("domainname", "")
    if dom in skipd or u["username"] in skipu: continue
    if u["address_type"] == 2:  # mailing list
        ml = lists_by_name.get(u["username"], {})
        lp = int(ml.get("list_privilege", 0) or 0)
        opts = "ltype=%s;lpriv=%s" % (ml.get("list_type", 0), lpriv.get(lp, "all"))
        if lp == 3 and senders.get(str(ml.get("id"))):
            opts += ";senders=" + ",".join(senders[str(ml["id"])])
        members = [ma(a["username"]) for a in inv["associations"]
                   if a["listname"] == u["username"]]
        row("mlist", u["username"], ma(u["username"]), "", "", "", "",
            u["real_name"] or "", ",".join(members), opts)
    elif u["address_type"] == 1:  # alias row sharing a maildir
        if u["username"] in alias_names: continue  # listed in aliases
        main = by_store.get(u["maildir_host"])
        row("alias", u["username"], ma(u["username"]), "", "", "", "",
            "", ma(main["username"]) if main else "?",
            "main=%s" % (main["username"] if main else ""))
    elif u["address_type"] == 0:
        if not u["maildir_host"]:
            out.write("# no store on the source, skipped: %s\n" % u["username"])
            continue
        q = u["max_size"] if qmode == "source" else int(qmode)
        kind = "shared" if u["username"] in shared else "user"
        opts = "priv=%d;status=%d;srcid=%d;srcdom=%d" % (
            u["privilege_bits"] or 0, u["address_status"] or 0, u["id"], u["domain_id"])
        if u.get("password"): opts += ";pwhash=" + u["password"]
        row(kind, u["username"], ma(u["username"]), u["maildir_host"],
            q, lang(u["lang"]), u["timezone"] or dtz,
            u["real_name"] or u["username"].split("@")[0], "", opts)
for a in inv["aliases"]:
    if a["aliasname"].rsplit("@", 1)[-1] in skipd: continue
    row("alias", a["aliasname"], ma(a["aliasname"]), "", "", "", "", "",
        ma(a["mainname"]), "main=%s" % a["mainname"])
out.close()
PY
	mv "$PLAN.tmp" "$PLAN"
	chmod 600 "$PLAN"
	log "plan: $(plan_rows domain | wc -l) domains, $(plan_rows user | wc -l) users," \
	    "$(plan_rows shared | wc -l) shared, $(plan_rows alias | wc -l) aliases," \
	    "$(plan_rows mlist | wc -l) lists, $(plan_rows domainstore | wc -l) domain stores"
	log "plan: review/edit $PLAN, then run 'provision'"
}

# ---------------------------------------------------------------- provision
quota_args() { # quota_args <quota_mb> -> --property arguments
	[[ -n $1 && $1 != 0 ]] || return 0
	printf -- '--property\nstoragequotalimit=%sMiB\n' "$1"
	printf -- '--property\nprohibitreceivequota=%sMiB\n' "$1"
	printf -- '--property\nprohibitsendquota=%sMiB\n' "$1"
}
cmd_provision() {
	[[ -f $PLAN ]] || die "run 'plan' first"
	need grommunio-admin; need openssl; need mysql
	[[ $DRYRUN -eq 1 ]] || { touch "$CRED" && chmod 600 "$CRED"; }
	local kind src dst store quota lang tz name extra opts
	while read_row; do
		[[ $kind == domain ]] || continue
		if [[ -n $(target_homedir "$dst") ]]; then
			log "provision: domain $dst exists"
		else
			try_run grommunio-admin domain create --create-role --maxUser 65536 \
				${name:+--title "$name"} "$dst"
		fi
	done <"$PLAN"
	while read_row; do
		[[ $kind == user || $kind == shared ]] || continue
		is_only "$src" || continue
		if [[ -n $(target_maildir "$dst") ]]; then
			log "provision: user $dst exists"
			continue
		fi
		local priv status; priv=$(opt_get "$opts" priv); priv=${priv:-0}
		status=$(opt_get "$opts" status); status=${status:-0}
		# --no-defaults: admin-api "defaults-system" may contain attributes
		# the CLI rejects (e.g. keycloak); privileges come from USER_PRIVS
		# shellcheck disable=SC2206
		local -a args=(--no-defaults $USER_PRIVS --lang "$lang"
		               --property "displayname=$name")
		mapfile -t -O ${#args[@]} args < <(quota_args "$quota")
		# e4a privilege_bits: 1 POP3/IMAP, 2 SMTP, 4 CHGPASSWD (same as
		# gromox), then 8 NO_MAPI, 16 NO_AS, 32 NO_WEB, 64 USRADM, 256 DOMADM,
		# 1024 ORGADM, 4096 SYSADM (e4a manage/backend/privilege.py) - unlike
		# gromox's 8 PUBADDR, 16 CHAT, ...; only the first three are shared.
		args+=(--pop3-imap "$(( (priv & 1) != 0 ))" --smtp "$(( (priv & 2) != 0 ))"
		       --changePassword "$(( (priv & 4) != 0 ))")
		(( priv & 16 )) && args+=(--privEas false)
		(( priv & 32 )) && args+=(--privWeb false)
		if [[ $kind == shared ]]; then
			args+=(--status shared)
		elif [[ $status != 0 ]]; then
			# e4a address_status != 0: account was not active there
			args+=(--status suspended)
		fi
		try_run grommunio-admin user create "${args[@]}" "$dst"
		[[ $TRY_OK -eq 1 ]] || continue
		note "$PROVISIONED" "$dst"
		[[ $DRYRUN -eq 1 ]] && continue
		local pwhash; pwhash=$(opt_get "$opts" pwhash)
		if [[ $PASSWORD_MODE == copy && $pwhash == \$* && $status == 0 ]]; then
			# gromox verifies with crypt(3); e4a hashes are yescrypt/sha512
			# crypt strings, so they can be carried over verbatim
			if sql "UPDATE users SET password=$(sql_lit "$pwhash") WHERE username=$(sql_lit "$dst")"; then
				printf '%s\t%s\t%s\n' "$dst" "(password copied from e4a)" "$kind" >>"$CRED"
			else
				FAILS=$((FAILS + 1)); log "FAILED: password copy for $dst"
				printf '%s\t%s\t%s\n' "$dst" "PASSWORD-NOT-SET" "$kind" >>"$CRED"
			fi
		else
			local pw; pw=$(gen_password)
			if printf '%s\n' "$pw" | grommunio-admin passwd --password-stdin "$dst" >/dev/null 2>>"$LOG"; then
				printf '%s\t%s\t%s\n' "$dst" "$pw" "$kind" >>"$CRED"
			else
				FAILS=$((FAILS + 1)); log "FAILED: passwd for $dst"
				printf '%s\t%s\t%s\n' "$dst" "PASSWORD-NOT-SET" "$kind" >>"$CRED"
			fi
		fi
		if [[ -n $tz ]]; then
			sql "UPDATE users SET timezone=$(sql_lit "$tz") WHERE username=$(sql_lit "$dst")" ||
				log "warning: could not set timezone for $dst"
		fi
	done <"$PLAN"
	while read_row; do
		[[ $kind == alias ]] || continue
		local main; main=$(opt_get "$opts" main)
		is_only "$src" "$main" || continue
		[[ $extra == "?" ]] && { log "provision: alias $dst has no main user, skipped"; continue; }
		if [[ -n $(sql "SELECT 1 FROM aliases WHERE aliasname=$(sql_lit "$dst")") ]]; then
			log "provision: alias $dst exists"; continue
		fi
		[[ -n $(target_maildir "$extra") ]] ||
			{ log "provision: alias $dst: main user $extra not on target, skipped"; FAILS=$((FAILS + 1)); continue; }
		try_run grommunio-admin user modify --alias "$dst" "$extra"
	done <"$PLAN"
	while read_row; do
		[[ $kind == mlist ]] || continue
		is_only "$src" || continue
		local -a margs=(); local m lp sd lt; local -a members=() sdrs=() keep=()
		IFS=, read -ra members <<<"$extra"
		for m in "${members[@]}"; do
			[[ -n $m ]] || continue
			# members in a migrated domain must exist on the target
			if is_target_domain "${m#*@}" && ! principal_exists "$m"; then
				log "provision: mlist $dst: member $m not on target, skipped"
				continue
			fi
			keep+=("$m")
		done
		if [[ -n $(sql "SELECT 1 FROM mlists WHERE listname=$(sql_lit "$dst")") ]]; then
			log "provision: mlist $dst exists, reconciling members"
			for m in "${keep[@]}"; do
				run grommunio-admin mlist add "$dst" recipient "$m" >/dev/null 2>&1 || true
			done
			continue
		fi
		lt=$(opt_get "$opts" ltype)
		case ${lt:-0} in
		0) ;;
		2) margs+=(-t domain) ;;
		*) log "provision: mlist $dst has e4a list_type $lt (group/class), created as normal list - check members"; ;;
		esac
		lp=$(opt_get "$opts" lpriv); [[ -n $lp ]] && margs+=(-p "$lp")
		for m in "${keep[@]}"; do margs+=(-r "$m"); done
		sd=$(opt_get "$opts" senders); IFS=, read -ra sdrs <<<"$sd"
		for m in "${sdrs[@]}"; do [[ -n $m ]] && margs+=(-s "$m"); done
		try_run grommunio-admin mlist create "${margs[@]}" "$dst"
	done <"$PLAN"
	log "provision: done, $FAILS failures; passwords in $CRED"
	[[ $FAILS -eq 0 ]]
}

# ----------------------------------------------------------------- transfer
check_space() { # check_space <source store> <target dir>
	local need_mb avail_mb cid sq
	cid=$(store_stat "$1" cid_mb); sq=$(store_stat "$1" sqlite_bytes)
	[[ -n $cid && -n $sq ]] || { log "warning: no size data for $1 in inventory"; return 0; }
	# schema upgrade may temporarily double the sqlite file
	need_mb=$(( cid + 2 * sq / 1048576 + 1024 ))
	avail_mb=$(df --output=avail -m "$2" | tail -1 | tr -d ' ')
	(( avail_mb > need_mb )) ||
		die "not enough space for $1: need ~${need_mb} MiB, ${avail_mb} MiB free on $2"
}
transfer_one() { # transfer_one <src store> <dst dir> <dst address> <src address>
	local src=$1 dst=$2 user=$3 srcuser=$4
	[[ $src == /?* ]] || die "refusing transfer: source store path '$src' for $srcuser"
	[[ $dst == /?* && -d $dst ]] || die "target dir '$dst' for $user missing (provision first)"
	if ! listed "$PROVISIONED" "$user" && ! listed "$TRANSFERRED" "$user" && [[ $FORCE -eq 0 ]]; then
		die "$user exists on the target but was not created by this tool; use -f to replace its store"
	fi
	check_space "$src" "$dst"
	# keep gromox away from the files: reject new operations, drop handles
	run gromox-mbop -u "$user" freeze || true
	run gromox-mbop -u "$user" unload || die "cannot unload $user; stop clients first"
	if [[ $SRC_MODE == archive ]]; then
		# offline transport: one <source address>.tar.zst per store made
		# on the e4a host AFTER e4a was stopped, with
		#   tar -C <store> --exclude=./eml --exclude=./ext --exclude=./fts
		#       --exclude=./dac --exclude=./tmp --exclude=./exmdb/midb.sqlite3
		#       --exclude=./exmdb/dac.sqlite3 -cf - . | zstd > <addr>.tar.zst
		# (exchange.sqlite3-wal/-shm are included on purpose)
		local ar=$SRC_ARCHIVE_DIR/$srcuser.tar.zst
		[[ -f $ar ]] || die "archive $ar missing"
		run tar --zstd -tf "$ar" >/dev/null || die "archive $ar is not readable"
		run rm -rf "$dst/exmdb" "$dst/cid" "$dst/config"
		run tar -C "$dst" --zstd -xf "$ar"
	else
		local -a ex=(--exclude=/eml/ --exclude=/ext/ --exclude=/fts/
			--exclude=/dac/ --exclude=/tmp/ --exclude=/exmdb/midb.sqlite3
			--exclude=/exmdb/dac.sqlite3)
		# the sqlite WAL holds committed data not yet in exchange.sqlite3;
		# it is useless from a live source (torn) but must come along in
		# the final sync so that sqlite can replay it on the target
		[[ $FINAL -eq 1 ]] || ex+=(--exclude='/exmdb/*-shm' --exclude='/exmdb/*-wal')
		# shellcheck disable=SC2086
		run rsync $RSYNC_OPTS --delete -e "ssh $SRC_SSH_OPTS -o BatchMode=yes" \
			"${ex[@]}" "$SRC_SSH:$src/" "$dst/"
	fi
	# e4a-only leftovers in case they were copied anyway
	run rm -rf "$dst/fts" "$dst/dac" "$dst/exmdb/dac.sqlite3"
	run chown -R "$GROMOX_USER:$GROMOX_GROUP" "$dst"
	run chmod -R u+rwX,g+rwX,o-rwx "$dst"
	run install -d -o "$GROMOX_USER" -g "$GROMOX_GROUP" -m 0770 \
		"$dst/eml" "$dst/ext" "$dst/tmp" "$dst/tmp/imap.rfc822" \
		"$dst/tmp/faststream" "$dst/config"
	# e4a's midb (IMAP index) is not carried over; gromox-midb needs an
	# existing midb.sqlite3 (it does not create one), so make a fresh one
	# that midb fills lazily on first IMAP/POP3 access
	run rm -f "$dst/exmdb/midb.sqlite3" "$dst/exmdb/midb.sqlite3-shm" \
		"$dst/exmdb/midb.sqlite3-wal"
	if [[ $user != @* ]]; then
		run gromox-mkmidb -f "$user"
		run chown "$GROMOX_USER:$GROMOX_GROUP" "$dst/exmdb/midb.sqlite3"
	fi
	note "$TRANSFERRED" "$user"
	[[ $FINAL -eq 1 ]] && note "$WORKDIR/final.lst" "$user"
	return 0
}
cmd_transfer() {
	[[ -f $PLAN && -f $INV ]] || die "run 'inventory' and 'plan' first"
	need gromox-mbop; need gromox-mkmidb; need python3
	if [[ $SRC_MODE == archive ]]; then need tar; need zstd; else need rsync; need ssh; fi
	if [[ $FINAL -eq 1 && $SRC_MODE != archive && $SKIP_SOURCE_CHECK -ne 1 ]]; then
		local running
		running=$(src_ssh "docker inspect -f '{{.State.Running}}' '$SRC_CONTAINER'" 2>/dev/null || echo unknown)
		[[ $running == false ]] ||
			die "final sync requires the e4a container to be stopped (state: $running); SKIP_SOURCE_CHECK=1 overrides"
	fi
	[[ $FINAL -eq 1 ]] && log "transfer: FINAL sync (WAL included)" ||
		log "transfer: pre-sync (source may be live; run again with --final after stopping e4a)"
	local kind src dst store quota lang tz name extra opts md
	while read_row; do
		case $kind in
		user|shared) is_only "$src" || continue
			md=$(target_maildir "$dst") || die "mysql lookup failed for $dst"
			[[ -n $md ]] || die "user $dst not provisioned"
			log "transfer: $src -> $dst ($md)"
			transfer_one "$store" "$md" "$dst" "$src" ;;
		domainstore) is_only "$src" || continue
			md=$(target_homedir "$dst") || die "mysql lookup failed for $dst"
			[[ -n $md ]] || die "domain $dst not provisioned"
			log "transfer: public store $src -> @$dst ($md)"
			transfer_one "$store" "$md" "@$dst" "@$src" ;;
		esac
	done <"$PLAN"
	log "transfer: done"
}

# -------------------------------------------------------------------- fixup
guid_pairs() { # all store GUID pairs source->target (users+lists+domains)
	# entryids may reference other mailboxes (delegate shortcuts, favorites),
	# so every migrated principal's GUID pair is applied to every store
	local kind src dst store quota lang tz name extra opts sid did tid
	while read_row; do
		case $kind in
		user|shared)
			sid=$(opt_get "$opts" srcid); [[ -n $sid ]] || continue
			tid=$(sql "SELECT id FROM users WHERE username=$(sql_lit "$dst")")
			[[ -n $tid ]] || continue
			printf -- '--guid\n%s=%s\n' "$(python3 "$HERE/e4a_store_fixup.py" guid private "$sid")" \
				"$(python3 "$HERE/e4a_store_fixup.py" guid private "$tid")" ;;
		domain)
			did=$(opt_get "$opts" srcdom); [[ -n $did ]] || continue
			tid=$(sql "SELECT id FROM domains WHERE domainname=$(sql_lit "$dst")")
			[[ -n $tid ]] || continue
			printf -- '--guid\n%s=%s\n' "$(python3 "$HERE/e4a_store_fixup.py" guid public "$did")" \
				"$(python3 "$HERE/e4a_store_fixup.py" guid public "$tid")" ;;
		esac
	done <"$PLAN"
}
fixup_one() { # fixup_one <dst address> <dst dir> <kind> <quota> <displayname>
	local user=$1 dst=$2 kind=$3 quota=$4 name=$5 db=$2/exmdb/exchange.sqlite3
	[[ -f $db ]] || { log "FAILED: $db missing"; return 1; }
	if ! listed "$WORKDIR/final.lst" "$user" && [[ $FORCE -eq 0 ]]; then
		log "FAILED: $user has no recorded final sync (transfer --final); -f overrides"
		return 1
	fi
	# the store must not be open in exmdb while we work on the sqlite file
	run gromox-mbop -u "$user" freeze || true
	run gromox-mbop -u "$user" unload || { log "FAILED: cannot unload $user"; return 1; }
	run python3 "$HERE/e4a_store_fixup.py" check --preflight "$db" ||
		{ log "FAILED: $user fails the schema-upgrade pre-flight"; return 1; }
	local -a dm=(); mapfile -t dm < <(dm_args)
	run python3 "$HERE/e4a_store_fixup.py" rewrite-perms "${dm[@]}" \
		--known-users "$WORKDIR/target-principals.lst" "$db" || return 1
	# delegates/send-as lists hold addresses too
	local f e
	for f in "$dst/config/delegates.txt" "$dst/config/sendas.txt"; do
		[[ -f $f ]] || continue
		for e in "${DOMAIN_MAP[@]}"; do
			[[ ${e%%=*} == "${e#*=}" ]] && continue
			run sed -i "s/@${e%%=*}\$/@${e#*=}/" "$f"
		done
	done
	# EX (X.500) participants carry source-system ids: rewrite to SMTP
	run python3 "$HERE/e4a_store_fixup.py" xlat-addrs --map "$EXMAP" "${dm[@]}" "$db" || return 1
	# persisted entryids embed the source store GUID (= MySQL id)
	run python3 "$HERE/e4a_store_fixup.py" rewrite-guids "${GUID_PAIRS[@]}" \
		--file "$dst/config/zarafa.dat" "$db" || return 1
	# web settings: shared-store list refers to source identities; drop it
	[[ -f $dst/config/zarafa.dat ]] &&
		run python3 "$HERE/e4a_store_fixup.py" web-settings --drop-shared "$dst/config/zarafa.dat"
	run chown -R "$GROMOX_USER:$GROMOX_GROUP" "$dst"
	run chmod -R u+rwX,g+rwX,o-rwx "$dst"
	# schema upgrade (EV-0 -> current) offline; ~36 s per GB of sqlite and
	# the file temporarily doubles. Auto-upgrade on first load would do
	# the same work while blocking exmdb.
	if [[ $kind == domainstore ]]; then
		run gromox-mkpublic -U -v "${user#@}" || return 1
	else
		run gromox-mkprivate -U -v "$user" || return 1
	fi
	run chown -R "$GROMOX_USER:$GROMOX_GROUP" "$dst/exmdb"
	run gromox-mbop -u "$user" thaw || true
	run gromox-mbop -u "$user" ping || return 1
	if [[ $kind != domainstore ]]; then
		# the copied store_properties carry e4a's quota/name: push the
		# provisioned values from MySQL into the store again
		local -a qa=(); mapfile -t qa < <(quota_args "$quota")
		run grommunio-admin user modify "${qa[@]}" --property "displayname=$name" "$user" >/dev/null ||
			log "warning: could not re-apply quota/displayname for $user"
	fi
	run gromox-mbop -u "$user" recalc-sizes || true
	run gromox-mbop -u "$user" unload || true
	note "$FIXEDUP" "$user"
	return 0
}
cmd_fixup() {
	[[ -f $INV && -f $PLAN ]] || die "run 'inventory' and 'plan' first"
	need python3; need gromox-mbop; need gromox-mkprivate; need grommunio-admin
	# principals that exist on the target (users, shared, lists, aliases)
	[[ $DRYRUN -eq 1 ]] || sql "SELECT username FROM users UNION
		SELECT aliasname FROM aliases UNION SELECT listname FROM mlists" \
		>"$WORKDIR/target-principals.lst"
	local -a dbs=() users=() dirs=() kinds=() quotas=() names=()
	local kind src dst store quota lang tz name extra opts md
	while read_row; do
		case $kind in
		user|shared) is_only "$src" || continue
			md=$(target_maildir "$dst") || die "mysql lookup failed for $dst" ;;
		domainstore) is_only "$src" || continue
			md=$(target_homedir "$dst") || die "mysql lookup failed for $dst"
			dst="@$dst" ;;
		*) continue ;;
		esac
		[[ -n $md && -f $md/exmdb/exchange.sqlite3 ]] || continue
		if listed "$FIXEDUP" "$dst" && [[ $FORCE -eq 0 ]]; then
			log "fixup: $dst already done, skipped (-f repeats)"; continue
		fi
		dbs+=("$md/exmdb/exchange.sqlite3"); users+=("$dst"); dirs+=("$md")
		kinds+=("$kind"); quotas+=("$quota"); names+=("$name")
	done <"$PLAN"
	[[ ${#dbs[@]} -gt 0 ]] || die "no transferred stores to fix up"
	log "fixup: scanning ${#dbs[@]} stores for EX addresses"
	local -a dm=(); mapfile -t dm < <(dm_args)
	declare -g -a GUID_PAIRS=(); mapfile -t GUID_PAIRS < <(guid_pairs)
	[[ ${#GUID_PAIRS[@]} -gt 0 ]] || die "no store GUID pairs (plan without srcid? regenerate with plan -f)"
	log "fixup: $(( ${#GUID_PAIRS[@]} / 2 )) store GUID pairs"
	if [[ $DRYRUN -eq 1 ]]; then
		run python3 "$HERE/e4a_store_fixup.py" scan-dn "${dbs[@]}"
	else
		python3 "$HERE/e4a_store_fixup.py" scan-dn "${dbs[@]}" >"$WORKDIR/exdns.json"
	fi
	run python3 "$HERE/e4a_store_fixup.py" build-map --inventory "$INV" \
		--dns "$WORKDIR/exdns.json" --org "$SRC_X500_ORG" "${dm[@]}" \
		--output "$EXMAP"
	local i
	for i in "${!dbs[@]}"; do
		log "fixup: ${users[$i]}"
		fixup_one "${users[$i]}" "${dirs[$i]}" "${kinds[$i]}" "${quotas[$i]}" "${names[$i]}" ||
			FAILS=$((FAILS + 1))
	done
	log "fixup: done, $FAILS failures"
	[[ $FAILS -eq 0 ]]
}

# ------------------------------------------------------------------- verify
cmd_verify() {
	[[ -f $INV && -f $PLAN ]] || die "run 'inventory' and 'plan' first"
	need python3; need sqlite3
	local counts=$INV
	if [[ $SRC_MODE != archive && $DRYRUN -eq 0 ]]; then
		# fresh counts from the (stopped) source rather than the inventory
		# taken before the cutover
		local users=""; local kind src dst store quota lang tz name extra opts
		while read_row; do
			[[ $kind == user || $kind == shared ]] && is_only "$src" && users+="${users:+,}$src"
		done <"$PLAN"
		counts=$WORKDIR/source-counts.json
		if ! src_ssh "python3 - --no-folders --stats-users '$users' --container '$SRC_CONTAINER' \
			--db '$SRC_DB' --container-prefix '$SRC_CONTAINER_PREFIX' \
			--host-prefix '$SRC_HOST_PREFIX'" <"$HERE/e4a_inventory.py" >"$counts" 2>>"$LOG"; then
			log "verify: live source counts unavailable, using inventory"; counts=$INV
		fi
	fi
	local kind src dst store quota lang tz name extra opts md db sf sm df dmc status
	printf '%-45s %10s %10s %10s %10s %s\n' mailbox src_fld dst_fld src_msg dst_msg status
	while read_row; do
		[[ $kind == user || $kind == shared || $kind == domainstore ]] || continue
		is_only "$src" || continue
		if [[ $kind == domainstore ]]; then md=$(target_homedir "$dst"); else md=$(target_maildir "$dst"); fi
		db=$md/exmdb/exchange.sqlite3
		read -r sf sm < <(python3 -c 'import json, sys
s = json.load(open(sys.argv[1])).get("stores", {}).get(sys.argv[2], {})
print(s.get("folders", "?"), s.get("messages", "?"))' "$counts" "$store")
		if [[ -n $md && -f $db ]]; then
			df=$(sqlite3 "$db" 'SELECT COUNT(*) FROM folders')
			dmc=$(sqlite3 "$db" 'SELECT COUNT(*) FROM messages')
		else
			df="-"; dmc="-"
		fi
		status=OK
		[[ $sf == "$df" && $sm == "$dmc" ]] || status=DIFF
		printf '%-45s %10s %10s %10s %10s %s\n' "$dst" "$sf" "$df" "$sm" "$dmc" "$status"
	done <"$PLAN"
}

case $CMD in
inventory) cmd_inventory ;;
plan) cmd_plan ;;
provision) cmd_provision ;;
transfer) cmd_transfer ;;
fixup) cmd_fixup ;;
verify) cmd_verify ;;
*) die "unknown command $CMD" ;;
esac
