#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 grommunio GmbH
#
# e4a_inventory.py - enumerate an exchange4all (Kopanion / kopano.cloud)
# installation: domains, users, aliases, mailing lists and the per-user
# gromox-format stores. Runs on the e4a *host* as root (needs read access
# to the storage directory and "docker exec" into the e4a container for the
# MySQL client). Emits one JSON document on stdout.
#
# The e4a MySQL schema is:
#   users.address_type   0 = mailbox, 1 = alias row sharing another user's
#                        maildir, 2 = mailing list (see table mlists)
#   users.address_status 0 = active
#   users.max_size       quota in MiB
# Store directories (users.maildir) are given with the in-container prefix
# (/opt/exchange4all/...), the host sees them under --host-prefix.

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time

PROPTAG_DISPLAY_NAME = 0x3001001F
FID_IPMSUBTREE = 9


def mysql_rows(args, query):
    cmd = ["docker", "exec", args.container, "mysql", "-uroot", "-N", "-B",
           args.db, "-e", query]
    out = subprocess.run(cmd, check=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, universal_newlines=True).stdout
    rows = []
    for line in out.splitlines():
        rows.append([None if f == "NULL" else f.replace("\\t", "\t")
                     .replace("\\n", "\n").replace("\\\\", "\\")
                     for f in line.split("\t")])
    return rows


def mysql_table(args, table, columns):
    rows = mysql_rows(args, "SELECT %s FROM %s" % (", ".join(columns), table))
    return [dict(zip(columns, r)) for r in rows]


def to_host(args, path):
    if path is None or path == "":
        return ""
    if path.startswith(args.container_prefix):
        return args.host_prefix + path[len(args.container_prefix):]
    return path


def ro_connect(path):
    # mode=ro sees committed data still sitting in the WAL (needs the -shm
    # to be writable, fine as root); immutable=1 ignores the WAL entirely
    # and is only the fallback for a read-only filesystem
    try:
        c = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        c.execute("SELECT 1 FROM configurations LIMIT 1").fetchall()
        return c
    except sqlite3.Error:
        return sqlite3.connect("file:%s?mode=ro&immutable=1" % path, uri=True)


def du_mb(path):
    total = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total // 1048576


def store_stats(path, with_folders):
    st = {"path": path, "exists": os.path.isdir(path)}
    if not st["exists"]:
        return st
    db = os.path.join(path, "exmdb", "exchange.sqlite3")
    st["sqlite_bytes"] = os.stat(db).st_size if os.path.exists(db) else 0
    st["sqlite_mtime"] = int(os.stat(db).st_mtime) if os.path.exists(db) else 0
    st["wal_bytes"] = os.stat(db + "-wal").st_size if os.path.exists(db + "-wal") else 0
    st["cid_mb"] = du_mb(os.path.join(path, "cid"))
    try:
        cid_files = len(os.listdir(os.path.join(path, "cid")))
    except OSError:
        cid_files = 0
    st["cid_files"] = cid_files
    try:
        st["config_files"] = sorted(os.listdir(os.path.join(path, "config")))
    except OSError:
        st["config_files"] = []
    if not os.path.exists(db):
        return st
    try:
        c = ro_connect(db)
        st["configurations"] = {int(k): (v.decode() if isinstance(v, bytes)
                                else v) for k, v in
                                c.execute("SELECT config_id, config_value "
                                          "FROM configurations")}
        st["folders"] = c.execute("SELECT COUNT(*) FROM folders").fetchone()[0]
        st["messages"] = c.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        st["message_bytes"] = c.execute("SELECT IFNULL(SUM(message_size),0) "
                                        "FROM messages").fetchone()[0]
        st["attachments"] = c.execute("SELECT COUNT(*) FROM attachments").fetchone()[0]
        st["rules"] = c.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        st["named_dups"] = c.execute(
            "SELECT COUNT(*) FROM (SELECT name_string FROM named_properties "
            "GROUP BY name_string COLLATE NOCASE HAVING COUNT(*) > 1)").fetchone()[0]
        st["allocated_eids"] = c.execute("SELECT COUNT(*) FROM allocated_eids").fetchone()[0]
        st["permissions"] = [{"folder_id": f, "username": u, "permission": p}
                             for f, u, p in c.execute(
                             "SELECT folder_id, username, permission "
                             "FROM permissions ORDER BY folder_id")]
        if with_folders:
            st["ipm_folders"] = [{"folder_id": fid, "name": name,
                                  "messages": c.execute(
                                  "SELECT COUNT(*) FROM messages WHERE "
                                  "parent_fid=?", (fid,)).fetchone()[0]}
                                 for fid, name in c.execute(
                                 "SELECT f.folder_id, p.propval FROM folders f "
                                 "LEFT JOIN folder_properties p ON "
                                 "p.folder_id=f.folder_id AND p.proptag=? "
                                 "WHERE f.parent_id=? ORDER BY f.folder_id",
                                 (PROPTAG_DISPLAY_NAME, FID_IPMSUBTREE))]
        c.close()
    except sqlite3.Error as e:
        st["sqlite_error"] = str(e)
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="kopanion_exchange4all_1")
    ap.add_argument("--db", default="email")
    ap.add_argument("--container-prefix", default="/opt/exchange4all")
    ap.add_argument("--host-prefix", default="/data/kopanion/e4a")
    ap.add_argument("--no-stores", action="store_true",
                    help="skip per-store sqlite/disk statistics")
    ap.add_argument("--no-folders", action="store_true",
                    help="skip the per-store top-level folder listing")
    ap.add_argument("--with-passwords", action="store_true",
                    help="include the users.password hashes (crypt format)")
    ap.add_argument("--stats-users", default="",
                    help="comma separated usernames: only compute store "
                         "statistics for these (default: all)")
    args = ap.parse_args()

    inv = {"generated": int(time.time()), "host": os.uname().nodename,
           "container": args.container, "host_prefix": args.host_prefix}
    inv["domains"] = mysql_table(args, "domains", [
        "id", "org_id", "domainname", "homedir", "max_size", "max_user",
        "title", "address", "admin_name", "tel", "create_day", "end_day",
        "privilege_bits", "domain_status", "domain_type"])
    inv["users"] = mysql_table(args, "users", [
        "id", "username", "real_name", "title", "memo", "domain_id",
        "group_id", "maildir", "max_size", "create_day", "lang", "timezone",
        "privilege_bits", "sub_type", "address_status", "address_type",
        "cell", "tel", "nickname", "homeaddress", "provider_id"])
    if args.with_passwords:
        pw = {r[0]: r[1] for r in mysql_rows(args, "SELECT username, password FROM users")}
        for u in inv["users"]:
            u["password"] = pw.get(u["username"], "")
    inv["aliases"] = mysql_table(args, "aliases", ["aliasname", "mainname"])
    inv["mlists"] = mysql_table(args, "mlists", [
        "id", "listname", "domain_id", "list_type", "list_privilege"])
    inv["associations"] = mysql_table(args, "associations",
                                      ["username", "list_id"])
    lists_by_id = {m["id"]: m["listname"] for m in inv["mlists"]}
    for a in inv["associations"]:
        a["listname"] = lists_by_id.get(a["list_id"], "")
    inv["list_senders"] = mysql_table(args, "permissions",
                                      ["username", "list_id"])
    inv["groups"] = mysql_table(args, "groups", [
        "id", "groupname", "domain_id", "title", "max_size", "max_user",
        "group_status"])
    for d in inv["domains"]:
        d["homedir_host"] = to_host(args, d["homedir"])
    for u in inv["users"]:
        u["maildir_host"] = to_host(args, u["maildir"])
        for k in ("id", "domain_id", "group_id", "max_size", "privilege_bits",
                  "sub_type", "address_status", "address_type"):
            u[k] = int(u[k]) if u[k] not in (None, "") else None

    if not args.no_stores:
        only = set(x.strip() for x in args.stats_users.split(",") if x.strip())
        seen = {}
        for u in inv["users"]:
            p = u["maildir_host"]
            u["store"] = p if p else None
            if only and u["username"] not in only:
                continue
            if p and p not in seen:
                seen[p] = store_stats(p, not args.no_folders)
        for d in inv["domains"]:
            p = d["homedir_host"]
            if only or not p or p in seen:
                continue
            seen[p] = store_stats(p, not args.no_folders)
        inv["stores"] = seen
        # orphaned store directories (not referenced by any user/domain)
        referenced = set(u["maildir_host"] for u in inv["users"]) | \
            set(d["homedir_host"] for d in inv["domains"])
        orphans = []
        for kind in ("u-data", "d-data"):
            base = os.path.join(args.host_prefix, "system", "var", "storage", kind)
            for root, dirs, files in os.walk(base):
                if "exmdb" in dirs:
                    if root not in referenced:
                        orphans.append(root)
                    dirs[:] = []
        inv["orphan_stores"] = sorted(orphans)

    json.dump(inv, sys.stdout, indent=1, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
