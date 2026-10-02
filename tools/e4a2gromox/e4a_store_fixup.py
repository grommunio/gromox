#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 grommunio GmbH
#
# e4a_store_fixup.py - target-side helpers for stores copied from an
# exchange4all (e4a) system into gromox. Operates directly on
# exmdb/exchange.sqlite3 and must only be used while the store is NOT
# loaded by gromox-exmdb (run "gromox-mbop -u user unload" first, or run
# before the user is ever served).
#
# Subcommands:
#   check          print configurations/counts of a store
#   scan-dn        list distinct EX ("/O=...") addresses used in a store
#   build-map      turn scanned DNs + the e4a inventory into a user map for
#                  "gromox-mbop exaddrxlat -m MAP"
#   rewrite-perms  rename permissions.username entries according to a
#                  domain map (source-domain=target-domain) and optionally
#                  drop entries for principals that do not exist on target
#   xlat-addrs     rewrite EX (X.500) participants to SMTP one-offs directly
#                  in the sqlite file: the same rules as "gromox-mbop
#                  exaddrxlat" (tools/kdbsub.cpp subst_addrs_entryids) applied
#                  to message properties, plus recipient rows and the
#                  creator/last-modifier entryids, which mbop does not cover.
#                  Being offline it neither rewrites cid files nor bumps change
#                  numbers, so it is the right tool before the store is ever
#                  served (a 680 GB mailbox would otherwise be rewritten).
#   rewrite-guids  gromox derives a store's database GUID from the MySQL
#                  user/domain id (rop_util_make_user_guid: XXXXXXXX-18a5-6f7b-
#                  bcdc-ea1ed03c5657 with time_low = id). Entryids persisted
#                  inside the store (default-folder, To-do search, reminders,
#                  free/busy, search criteria, web settings) therefore embed the
#                  SOURCE id and are rejected by zcore on the target
#                  (MAPI_E_INVALID_PARAMETER). This replaces the old GUIDs by
#                  the target ones, in binary and hex form, in all property
#                  tables and in extra files (config/zarafa.dat).
#   web-settings   edit the grommunio-web/Kopano-WebApp settings JSON kept in
#                  config/zarafa.dat: --drop-shared removes the shared-store
#                  list (it references other mailboxes by source identity;
#                  users re-add them).
#
# DN layout produced by e4a:
#   /O=<org>/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/
#   CN=<domain_id as 8 hex digits, little endian><user_id likewise>-<LOCALPART>
# The ids refer to the *source* MySQL ids; they are meaningless on the target,
# which is why every EX participant has to be rewritten to SMTP.

import argparse
import json
import re
import sqlite3
import sys

RCPT_ADDR_TAG = 0x3003001F   # PR_EMAIL_ADDRESS

# --- EX -> SMTP translation ---------------------------------------------
# propsets as in gromox tools/kdbsub.cpp: (addrtype, email, entryid,
# searchkey, smtp, displayname); None = property does not exist for the set
PROPSETS = (
    (0x0064001F, 0x0065001F, 0x00410102, 0x003B0102, 0x5D02001F, 0x0042001F),  # sent repr
    (0x0066001F, 0x0067001F, 0x005B0102, 0x005C0102, None, 0x005A001F),        # orig sender
    (0x0068001F, 0x0069001F, 0x005E0102, 0x005F0102, None, 0x005D001F),        # orig sent repr
    (0x0075001F, 0x0076001F, 0x003F0102, 0x00510102, None, 0x0040001F),        # received by
    (0x0077001F, 0x0078001F, 0x00430102, 0x00520102, None, 0x0044001F),        # rcvd repr
    (0x0079001F, 0x007A001F, 0x004C0102, 0x00560102, None, 0x004D001F),        # orig author
    (0x007B001F, 0x007C001F, 0x10120102, None, None, None),                    # orig intended
    (0x0C1E001F, 0x0C1F001F, 0x0C190102, 0x0C1D0102, 0x5D01001F, 0x0C1A001F),  # sender
    (0x3002001F, 0x3003001F, 0x0FFF0102, 0x300B0102, 0x39FE001F, 0x3001001F),  # bare/recipient
)
RCPT_SET = PROPSETS[-1]
# contact items: PSETID_Address Email{1,2,3}{AddressType,EmailAddress,
# OriginalEntryId} (PidLid 0x8082/0x8083/0x8085, 0x8092/.., 0x80A2/..) are
# named properties; their propids are per store (named_properties)
CONTACT_LIDS = ((0x8082, 0x8083, 0x8085), (0x8092, 0x8093, 0x8095),
                (0x80A2, 0x80A3, 0x80A5))
PSETID_ADDRESS = "00062004-0000-0000-c000-000000000046"
PR_CREATOR_ENTRYID, PR_CREATOR_NAME = 0x3FF90102, 0x3FF8001F
PR_LAST_MODIFIER_ENTRYID, PR_LAST_MODIFIER_NAME = 0x3FFB0102, 0x3FFA001F
MUID_OOP = bytes.fromhex("812b1fa4bea310199d6e00dd010f5402")
MUID_EMSAB = bytes.fromhex("dca740c8c042101ab4b908002b2fe182")


def oneoff_entryid(display, addr):
    # EXT_PUSH::p_oneoff_eid: flags, muidOOP, version, ctrl_flags
    # (MAPI_ONE_OFF_NO_RICH_INFO|MAPI_ONE_OFF_UNICODE), 3x UTF-16LE strings
    def w(x):
        return (x or "").encode("utf-16-le") + b"\0\0"
    return (b"\0\0\0\0" + MUID_OOP + b"\0\0" + b"\x01\x80" +
            w(display) + w("SMTP") + w(addr))


def searchkey(addr):
    return ("SMTP:" + addr.upper()).encode("utf-8") + b"\0"


def emsab_dn(blob):
    # EXT_PUSH::p_abk_eid: flags(4) muidEMSAB(16) version(4)=1 type(4) dn\0
    if not isinstance(blob, bytes) or len(blob) < 29 or blob[4:20] != MUID_EMSAB:
        return None
    dn = blob[28:].split(b"\0", 1)[0]
    try:
        return dn.decode("ascii")
    except UnicodeDecodeError:
        return None


class Translator:
    def __init__(self, mapfile, strict, dmap=None):
        self.map = {}
        for e in json.load(open(mapfile)):
            if e.get("dn") and e.get("to"):
                self.map[e["dn"] if strict else e["dn"].upper()] = e["to"]
        self.strict = strict
        self.dmap = dmap or {}
        self.n_sets = self.n_rows = self.n_creator = 0
        self.unmapped = {}

    def lookup(self, dn):
        return self.map.get(dn if self.strict else dn.upper())

    def process(self, props, pset):
        """props: {proptag: value} of one object; returns list of
        (proptag, value) to write, or []"""
        at, em, eid, sk, smtp, dname = pset
        addr = text(props.get(smtp)) if smtp else None
        out = []
        if addr:
            # existing SMTP address is the truth (as in gromox), but it may
            # still need the domain rename
            mapped = map_address(addr, self.dmap)
            if mapped != addr:
                out.append((smtp, mapped))
                addr = mapped
        if not addr:
            atype = text(props.get(at))
            dn = text(props.get(em))
            if atype is not None and atype.upper() == "SMTP" and dn and "@" in dn:
                # plain SMTP participant: only the domain rename applies
                mapped = map_address(dn, self.dmap)
                return [(em, mapped)] if mapped != dn else []
            if atype is None or atype.upper() != "EX":
                return []
            if dn is None:
                return []
            addr = self.lookup(dn)
            if addr is None:
                if dn.upper().startswith("/O="):
                    self.unmapped[dn] = self.unmapped.get(dn, 0) + 1
                return []
        cur_at, cur_em = text(props.get(at)), text(props.get(em))
        if cur_at is not None and cur_at.upper() == "SMTP" and cur_em == addr:
            return out  # already a plain SMTP participant
        out += [(at, "SMTP"), (em, addr)]
        display = text(props.get(dname)) if dname else None
        if eid:
            out.append((eid, oneoff_entryid(display or addr, addr)))
        if sk:
            out.append((sk, searchkey(addr)))
        return out

    def process_entryid(self, props, eid_tag, name_tag):
        dn = emsab_dn(props.get(eid_tag))
        if dn is None:
            return []
        addr = self.lookup(dn)
        if addr is None:
            self.unmapped[dn] = self.unmapped.get(dn, 0) + 1
            return []
        return [(eid_tag, oneoff_entryid(text(props.get(name_tag)) or addr, addr))]


def contact_propsets(c):
    """resolve the Email1..3 named properties of this store into propsets
    (addrtype, email, entryid, None, None, displayname=None)"""
    ids = {}
    for pid, name in c.execute("SELECT propid, name_string FROM named_properties "
                               "WHERE name_string LIKE ?",
                               ("GUID=%s,LID=%%" % PSETID_ADDRESS,)):
        try:
            ids[int(name.rsplit("=", 1)[1])] = pid
        except ValueError:
            pass
    sets = []
    for at, em, eid in CONTACT_LIDS:
        if at in ids and em in ids:
            sets.append(((ids[at] << 16) | 0x001F, (ids[em] << 16) | 0x001F,
                         ((ids[eid] << 16) | 0x0102) if eid in ids else None,
                         None, None, None))
    return sets


def chunked_ids(c, table, col, size):
    ids = [r[0] for r in c.execute("SELECT %s FROM %s ORDER BY %s" % (col, table, col))]
    for i in range(0, len(ids), size):
        yield ids[i], ids[i + size - 1] if i + size - 1 < len(ids) else ids[-1]


def xlat_table(c, tr, table, idcol, lo, hi, tags, work):
    """load rows of one id range, run work(props)->updates, write back"""
    q = ("SELECT %s, proptag, propval FROM %s WHERE %s BETWEEN ? AND ? AND "
         "proptag IN (%s)" % (idcol, table, idcol, ",".join(str(t) for t in tags)))
    objs = {}
    for oid, tag, val in c.execute(q, (lo, hi)):
        objs.setdefault(oid, {})[tag] = val
    ups = []
    for oid, props in objs.items():
        for tag, val in work(props):
            if props.get(tag) == val:
                continue
            ups.append((oid, tag, val))
    if ups:
        c.executemany("INSERT OR REPLACE INTO %s (%s, proptag, propval) "
                      "VALUES (?, ?, ?)" % (table, idcol), ups)
    return len(objs), len(ups)


def cmd_xlat_addrs(args):
    tr = Translator(args.map, args.strict, parse_domain_map(args.domain_map))
    c = rw_connect(args.db)
    csets = contact_propsets(c)
    c.execute("PRAGMA journal_mode=OFF" if args.unsafe else "PRAGMA journal_mode=DELETE")
    c.execute("PRAGMA synchronous=OFF")
    msg_tags = set()
    for ps in tuple(PROPSETS) + tuple(csets):
        msg_tags.update(t for t in ps if t)
    msg_tags.update((PR_CREATOR_ENTRYID, PR_CREATOR_NAME,
                     PR_LAST_MODIFIER_ENTRYID, PR_LAST_MODIFIER_NAME))

    def msg_work(props):
        out = []
        for ps in tuple(PROPSETS) + tuple(csets):
            out.extend(tr.process(props, ps))
        out.extend(tr.process_entryid(props, PR_CREATOR_ENTRYID, PR_CREATOR_NAME))
        out.extend(tr.process_entryid(props, PR_LAST_MODIFIER_ENTRYID,
                                      PR_LAST_MODIFIER_NAME))
        return out

    def rcpt_work(props):
        return tr.process(props, RCPT_SET)

    tm = tu = rm = ru = 0
    for lo, hi in chunked_ids(c, "messages", "message_id", args.chunk):
        n, u = xlat_table(c, tr, "message_properties", "message_id", lo, hi,
                          sorted(msg_tags), msg_work)
        tm += n; tu += u
        c.commit()
    for lo, hi in chunked_ids(c, "recipients", "recipient_id", args.chunk * 4):
        n, u = xlat_table(c, tr, "recipients_properties", "recipient_id", lo, hi,
                          [t for t in RCPT_SET if t], rcpt_work)
        rm += n; ru += u
        c.commit()
    c.close()
    sys.stderr.write("xlat-addrs %s: %d messages scanned, %d property rows "
                     "written; %d recipients scanned, %d rows written; %d "
                     "distinct unmapped EX DNs\n" % (args.db, tm, tu, rm, ru,
                                                     len(tr.unmapped)))
    for dn, n in sorted(tr.unmapped.items(), key=lambda kv: -kv[1])[:40]:
        sys.stderr.write("  unmapped %6d  %s\n" % (n, dn))


# --- store GUID rewrite ------------------------------------------------------
GUID_PRIVATE_TAIL = "a5187b6fbcdcea1ed03c5657"   # gx_dbguid_store_private
GUID_PUBLIC_TAIL = "0afb7df6919249886aa738ce"    # gx_dbguid_store_public


def store_guid_hex(kind, dbid):
    """hex string (as serialized, little-endian time_low) of
    rop_util_make_user_guid / rop_util_make_domain_guid"""
    tail = GUID_PRIVATE_TAIL if kind == "private" else GUID_PUBLIC_TAIL
    return int(dbid).to_bytes(4, "little").hex() + tail


class GuidRewriter:
    def __init__(self, pairs):
        self.bin = [(bytes.fromhex(o), bytes.fromhex(n)) for o, n in pairs]
        self.txt = []
        for o, n in pairs:
            self.txt.append((o.lower(), n.lower()))
            self.txt.append((o.upper(), n.upper()))
        self.hits = 0

    def blob(self, v):
        for o, n in self.bin:
            if o in v:
                self.hits += v.count(o)
                v = v.replace(o, n)
        for o, n in self.txt:  # hex-encoded entryids inside binary JSON etc.
            ob, nb = o.encode(), n.encode()
            if ob in v:
                self.hits += v.count(ob)
                v = v.replace(ob, nb)
        return v

    def text(self, v):
        for o, n in self.txt:
            if o in v:
                self.hits += v.count(o)
                v = v.replace(o, n)
        return v


def cmd_rewrite_guids(args):
    pairs = []
    for it in args.guid or []:
        o, n = it.split("=", 1)
        if len(o) != 32 or len(n) != 32:
            raise SystemExit("bad --guid %r (want 32 hex = 32 hex)" % it)
        pairs.append((o.lower(), n.lower()))
    gr = GuidRewriter(pairs)
    c = rw_connect(args.db)
    c.execute("PRAGMA synchronous=OFF")
    changed = 0
    # binary properties anywhere; text properties only on store/folder level
    # (that is where clients persist hex entryids; message bodies are cid
    # files anyway)
    for table, key in (("store_properties", "rowid"), ("folder_properties", "rowid"),
                       ("message_properties", "rowid"), ("attachment_properties", "rowid"),
                       ("recipients_properties", "rowid")):
        rows = c.execute("SELECT rowid, propval FROM %s WHERE typeof(propval)='blob'"
                         % table).fetchall()
        ups = []
        for rid, v in rows:
            nv = gr.blob(v)
            if nv != v:
                ups.append((nv, rid))
        if ups:
            c.executemany("UPDATE %s SET propval=? WHERE rowid=?" % table, ups)
        changed += len(ups)
        c.commit()
    for table in ("store_properties", "folder_properties"):
        rows = c.execute("SELECT rowid, propval FROM %s WHERE typeof(propval)='text'"
                         % table).fetchall()
        ups = [(gr.text(v), rid) for rid, v in rows if gr.text(v) != v]
        if ups:
            c.executemany("UPDATE %s SET propval=? WHERE rowid=?" % table, ups)
        changed += len(ups)
    for table, col in (("folders", "search_criteria"), ("rules", "condition"),
                       ("rules", "actions")):
        rows = c.execute("SELECT rowid, %s FROM %s WHERE %s IS NOT NULL" % (col, table, col)).fetchall()
        ups = []
        for rid, v in rows:
            if isinstance(v, bytes):
                nv = gr.blob(v)
                if nv != v:
                    ups.append((nv, rid))
        if ups:
            c.executemany("UPDATE %s SET %s=? WHERE rowid=?" % (table, col), ups)
        changed += len(ups)
    c.commit()
    c.close()
    files = 0
    for f in args.file or []:
        try:
            b = open(f, "rb").read()
        except OSError:
            continue
        nb = gr.blob(b)
        if nb != b:
            open(f, "wb").write(nb)
            files += 1
    sys.stderr.write("rewrite-guids %s: %d GUID occurrences replaced in %d rows, "
                     "%d files\n" % (args.db, gr.hits, changed, files))


def cmd_web_settings(args):
    """zarafa.dat = EXT_PUSH tpropval_array (+ tarray_set); the settings JSON
    is a NUL-terminated UTF-8 string without length prefix, so it can be
    edited in place as long as the terminator stays."""
    b = open(args.file, "rb").read()
    out, pos, edits = bytearray(), 0, 0
    while True:
        i = b.find(b'{"settings"', pos)
        if i < 0:
            out += b[pos:]
            break
        end = b.find(b"\0", i)
        if end < 0:
            out += b[pos:]
            break
        try:
            j = json.loads(b[i:end].decode("utf-8"))
        except ValueError:
            out += b[pos:end]
            pos = end
            continue
        if args.drop_shared:
            h = j.get("settings", {}).get("zarafa", {}).get("v1", {}).get("contexts", {}).get("hierarchy", {})
            if "shared_stores" in h:
                del h["shared_stores"]
                edits += 1
        out += b[pos:i] + json.dumps(j, separators=(",", ":")).encode("utf-8")
        pos = end
    if edits:
        open(args.file, "wb").write(bytes(out))
    sys.stderr.write("web-settings %s: %d edits\n" % (args.file, edits))


DN_RE = re.compile(r"^/O=([^/]+)/OU=[^/]+/CN=RECIPIENTS/CN=([0-9A-F]{8})"
                   r"([0-9A-F]{8})(?:-(.*))?$", re.I)


def le_hex_to_int(h):
    return int.from_bytes(bytes.fromhex(h), "little")


def parse_dn(dn):
    m = DN_RE.match(dn)
    if m is None:
        return None
    return {"org": m.group(1), "domain_id": le_hex_to_int(m.group(2)),
            "user_id": le_hex_to_int(m.group(3)), "suffix": m.group(4) or ""}


def rw_connect(path):
    return sqlite3.connect(path, timeout=30)


def ro_connect(path):
    return sqlite3.connect("file:%s?mode=ro" % path, uri=True)


def text(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace").rstrip("\0")
    return v


def cmd_check(args):
    c = ro_connect(args.db)
    print("configurations:")
    for k, v in c.execute("SELECT config_id, config_value FROM configurations "
                          "ORDER BY config_id"):
        print("  %2d = %s" % (k, text(v)))
    for t in ("folders", "messages", "attachments", "permissions", "rules",
              "named_properties", "allocated_eids"):
        print("%-18s %d" % (t, c.execute("SELECT COUNT(*) FROM " + t).fetchone()[0]))
    print("sqlite_master tables: %s" % ", ".join(
        r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                "ORDER BY name")))
    # pre-flight for the gromox schema upgrade (lib/dbop_sqlite.cpp):
    # step 12 creates UNIQUE INDEX on named_properties(name_string) (NOCASE)
    # and step 15 needs a non-empty allocated_eids table
    dups = c.execute("SELECT name_string, COUNT(*) FROM named_properties "
                     "GROUP BY name_string COLLATE NOCASE HAVING COUNT(*) > 1").fetchall()
    eids = c.execute("SELECT COUNT(*) FROM allocated_eids").fetchone()[0]
    print("preflight: duplicate named_properties: %d, allocated_eids rows: %d -> %s"
          % (len(dups), eids, "OK" if not dups and eids else "FAIL"))
    for n, k in dups[:20]:
        print("  dup: %r x%d" % (n, k))
    if args.preflight and (dups or not eids):
        sys.exit(3)


def scan_dns(path):
    c = ro_connect(path)
    counts = {}
    tags = set(ps[1] for ps in PROPSETS[:-1]) | set(ps[1] for ps in contact_propsets(c))
    for tag in sorted(tags):
        for v, n in c.execute("SELECT propval, COUNT(*) FROM message_properties "
                              "WHERE proptag=? AND (propval LIKE '/O=%' OR "
                              "propval LIKE '/o=%') GROUP BY propval", (tag,)):
            counts[text(v)] = counts.get(text(v), 0) + n
    for v, n in c.execute("SELECT propval, COUNT(*) FROM recipients_properties "
                          "WHERE proptag=? AND (propval LIKE '/O=%' OR "
                          "propval LIKE '/o=%') GROUP BY propval", (RCPT_ADDR_TAG,)):
        counts[text(v)] = counts.get(text(v), 0) + n
    # address-book entryids of creator / last modifier
    for (v,) in c.execute("SELECT propval FROM message_properties WHERE proptag "
                          "IN (?, ?)", (PR_CREATOR_ENTRYID, PR_LAST_MODIFIER_ENTRYID)):
        dn = emsab_dn(v)
        if dn:
            counts[dn] = counts.get(dn, 0) + 1
    c.close()
    return counts


def cmd_scan_dn(args):
    total = {}
    for db in args.db:
        for dn, n in scan_dns(db).items():
            total[dn] = total.get(dn, 0) + n
    json.dump([{"dn": dn, "count": n} for dn, n in
               sorted(total.items(), key=lambda kv: -kv[1])],
              sys.stdout, indent=1)
    sys.stdout.write("\n")


def parse_domain_map(items):
    m = {}
    for it in items or []:
        if "=" not in it:
            raise SystemExit("bad --domain-map entry %r (want src=dst)" % it)
        s, d = it.split("=", 1)
        m[s.lower()] = d.lower()
    return m


def map_address(addr, dmap):
    if "@" not in addr:
        return addr
    lp, dom = addr.rsplit("@", 1)
    return "%s@%s" % (lp, dmap.get(dom.lower(), dom))


def cmd_build_map(args):
    inv = json.load(open(args.inventory))
    dmap = parse_domain_map(args.domain_map)
    users_by_id = {u["id"]: u for u in inv["users"]}
    domains_by_id = {int(d["id"]): d["domainname"] for d in inv["domains"]}
    dns = json.load(open(args.dns)) if args.dns else []
    out, unresolved = [], []
    seen = set()
    # 1. every known user/alias/mlist of the source gets a DN entry
    for u in inv["users"]:
        if u["id"] is None:
            continue
        dom = domains_by_id.get(u["domain_id"], "")
        dn = ("/O=%s/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/"
              "CN=RECIPIENTS/CN=%s%s-%s" % (
                  args.org, u["domain_id"].to_bytes(4, "little").hex(),
                  u["id"].to_bytes(4, "little").hex(),
                  u["username"].split("@", 1)[0])).upper()
        out.append({"dn": dn, "to": map_address(u["username"], dmap),
                    "na": u["username"]})
        seen.add(dn.upper())
    # 2. DNs seen in message data that do not belong to a current user
    #    (deleted accounts): synthesize the address from the DN suffix
    for e in dns:
        dn = e["dn"]
        if dn.upper() in seen:
            continue
        p = parse_dn(dn)
        if p is None:
            unresolved.append(dn)
            continue
        u = users_by_id.get(p["user_id"])
        dom = domains_by_id.get(p["domain_id"])
        if u is not None and u["domain_id"] == p["domain_id"]:
            to = map_address(u["username"], dmap)
        elif p["suffix"] and dom:
            to = map_address("%s@%s" % (p["suffix"].lower(), dom), dmap)
        else:
            unresolved.append(dn)
            continue
        out.append({"dn": dn, "to": to, "deleted": u is None})
        seen.add(dn.upper())
    json.dump(out, open(args.output, "w"), indent=1)
    sys.stderr.write("map: %d entries written to %s, %d unresolved DNs\n"
                     % (len(out), args.output, len(unresolved)))
    for dn in unresolved:
        sys.stderr.write("  unresolved: %s\n" % dn)


def cmd_rewrite_perms(args):
    dmap = parse_domain_map(args.domain_map)
    keep = None
    if args.known_users:
        keep = set(l.strip().lower() for l in open(args.known_users)
                   if l.strip())
    c = rw_connect(args.db)
    rows = c.execute("SELECT member_id, folder_id, username FROM permissions").fetchall()
    changed = dropped = 0
    for mid, fid, user in rows:
        user = text(user)
        if user in ("default", "anonymous", "") or "@" not in user:
            continue
        new = map_address(user, dmap)
        if keep is not None and new.lower() not in keep:
            if args.drop_unknown:
                c.execute("DELETE FROM permissions WHERE member_id=?", (mid,))
                dropped += 1
            else:
                sys.stderr.write("warning: fid %d: principal %s not on target\n"
                                 % (fid, new))
            continue
        if new != user:
            # the (folder_id, username) index is UNIQUE; merge if the target
            # principal already has an entry on this folder
            dup = c.execute("SELECT member_id FROM permissions WHERE folder_id=? "
                            "AND username=?", (fid, new)).fetchone()
            if dup:
                c.execute("UPDATE permissions SET permission = permission | "
                          "(SELECT permission FROM permissions WHERE member_id=?) "
                          "WHERE member_id=?", (mid, dup[0]))
                c.execute("DELETE FROM permissions WHERE member_id=?", (mid,))
                dropped += 1
            else:
                c.execute("UPDATE permissions SET username=? WHERE member_id=?",
                          (new, mid))
                changed += 1
    c.commit()
    c.close()
    sys.stderr.write("permissions: %d renamed, %d dropped\n" % (changed, dropped))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    sub.required = True  # (python 3.6 has no required= keyword)
    p = sub.add_parser("guid")  # print store GUID hex for the shell driver
    p.add_argument("kind", choices=["private", "public"])
    p.add_argument("id", type=int)
    p = sub.add_parser("check"); p.add_argument("db")
    p.add_argument("--preflight", action="store_true",
                   help="exit 3 when the store would fail the schema upgrade")
    p = sub.add_parser("scan-dn"); p.add_argument("db", nargs="+")
    p = sub.add_parser("build-map")
    p.add_argument("--inventory", required=True)
    p.add_argument("--dns", help="output of scan-dn (JSON)")
    p.add_argument("--org", default="My Organization",
                   help="source x500_org_name (e4a zcore.cfg X500_ORG_NAME)")
    p.add_argument("--domain-map", action="append", metavar="SRC=DST")
    p.add_argument("--output", required=True)
    p = sub.add_parser("xlat-addrs")
    p.add_argument("db")
    p.add_argument("--map", required=True, help="user map JSON (dn/to)")
    p.add_argument("--domain-map", action="append", metavar="SRC=DST",
                   help="also rename existing SMTP addresses of these domains")
    p.add_argument("--strict", action="store_true",
                   help="case-sensitive DN matching like gromox-mbop")
    p.add_argument("--chunk", type=int, default=20000)
    p.add_argument("--unsafe", action="store_true",
                   help="no rollback journal (faster; only with a backup)")
    p = sub.add_parser("rewrite-guids")
    p.add_argument("db")
    p.add_argument("--guid", action="append", metavar="OLDHEX=NEWHEX",
                   help="32-hex-digit store GUID pair as serialized (see store_guid_hex)")
    p.add_argument("--file", action="append", help="extra file to patch (zarafa.dat)")
    p = sub.add_parser("web-settings")
    p.add_argument("file", help="config/zarafa.dat")
    p.add_argument("--drop-shared", action="store_true")
    p = sub.add_parser("rewrite-perms")
    p.add_argument("db")
    p.add_argument("--domain-map", action="append", metavar="SRC=DST")
    p.add_argument("--known-users", help="file with one target address per line")
    p.add_argument("--drop-unknown", action="store_true")
    args = ap.parse_args()
    if args.cmd == "guid":
        print(store_guid_hex(args.kind, args.id)); return
    {"check": cmd_check, "scan-dn": cmd_scan_dn, "build-map": cmd_build_map,
     "rewrite-perms": cmd_rewrite_perms, "xlat-addrs": cmd_xlat_addrs,
     "rewrite-guids": cmd_rewrite_guids, "web-settings": cmd_web_settings}[args.cmd](args)


if __name__ == "__main__":
    main()
