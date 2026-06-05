#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 grommunio GmbH
# This file is part of Gromox.
"""
gromox_imap_validate.py – concurrency and functional validator for gromox-imap

Standalone (stdlib only, Python 3.6+) program for validating IMAP
race/latency fixes, plus a functional regression and a concurrent
load/stress run.

Checks
------
  FUNC   : broad functional regression in isolated folders (SELECT/STATUS/APPEND/
           FETCH/ENVELOPE/BODYSTRUCTURE/nested message/rfc822 BODY[2.x]/SEARCH/
           ESEARCH/SEARCHRES/STORE keyword/UID MOVE/LIST-EXTENDED/NAMESPACE/
           ENABLE rev2 + rev2 no-RECENT).
  R1     : cross-connection rfc822 subpart delete race. Many connections issue a
           wide "FETCH 1:* BODY.PEEK[2]" whose total exceeds the 64 MiB per-conn
           body-cache budget, forcing the server to persist+evict rfc822 subparts
           to tmp/imap.rfc822. Every fetched part must byte-match a golden
           single-connection baseline -- never NIL, never divergent. Pre-fix, one
           connection's end-of-command cleanup deleted the shared backing file
           another was streaming -> NIL/garbage.
  R1-anch: an independent known-good anchor (the exact marker bytes we APPENDed)
           via a ranged partial fetch -- guards against *uniform* corruption that
           a golden-vs-worker comparison alone could not catch.
  R1-iso : (needs --maildir) DIRECT isolation proof -- every backing file seen in
           tmp/imap.rfc822 during the storm is "<serial>_..." AND at least two
           DISTINCT serials are observed (a regression collapsing all connections
           to one serial would re-open the race and is caught here).
  R5     : (needs --maildir) latency fix. Under-budget fetches must create ZERO
           NEW files in tmp/imap.rfc822 (pre-fix wrote one per fragment); an
           over-budget wide fetch must create them (mechanism intact) and clean
           them up. Uses set-difference vs a baseline snapshot, not an
           instantaneous count, to avoid a sub-ms sampling race.
  R2     : async-notification LIVENESS (honest scope: not a discriminating test
           of the unlocked-precheck race). A poller spins NOOP while another
           connection fires rapid distinct-keyword STOREs; every change must be
           observed.
  LOAD   : sustained concurrent FETCH/SEARCH/STORE mix; reports throughput,
           reconnects, errors (must be 0), NIL bodies (must be 0), optional RSS
           timeline (--pid) and a post-run tmp/imap.rfc822 leak check (--maildir).

Safety
------
All work happens in dedicated folders (GXVALIDATE*). They are guarded: if such a
folder already exists and is non-empty the run aborts unless --force is given.
They are deleted at the end (use --keep to retain). ~90 MiB is appended
temporarily and removed. INBOX is never touched.

Examples
--------
	# full run on the server (enables filesystem + memory checks)
	python3 gromox_imap_validate.py --host localhost --user U --pass SECRET \
		--maildir /var/lib/gromox/user/grommun.io/imaptest --pid "$(pidof imap)"
	# protocol-only from any client
	python3 gromox_imap_validate.py --host mail.example.com --user U --pass SECRET
"""
import argparse, hashlib, os, random, re, socket, ssl, sys, threading, time

CRLF = b"\r\n"
BUDGET = 64 * 1024 * 1024  # gromox mjson_io m_budget


# ---------------------------------------------------------------------------
# Minimal raw IMAP client
# ---------------------------------------------------------------------------
class IMAPError(Exception):
	pass


class Client:
	_counter = 0
	_counter_lock = threading.Lock()

	def __init__(self, cfg):
		self.cfg = cfg
		self.sock = None
		self.rf = None
		self.greeting = None

	def connect(self):
		raw = socket.create_connection((self.cfg.host, self.cfg.port), timeout=self.cfg.timeout)
		if self.cfg.ssl:
			ctx = ssl._create_unverified_context()
			raw = ctx.wrap_socket(raw, server_hostname=self.cfg.host)
		raw.settimeout(self.cfg.timeout)
		self.sock = raw
		self.rf = raw.makefile("rb")
		self.greeting = self.rf.readline()
		if not self.greeting.startswith(b"* OK"):
			raise IMAPError("bad greeting: %r" % self.greeting)
		return self

	def login_select(self, folder=None):
		self.connect()
		self.cmd("LOGIN %s %s" % (_q(self.cfg.user), _q(self.cfg.password)))
		if folder:
			self.cmd("SELECT %s" % _q(folder))
		return self

	def _tag(self):
		with Client._counter_lock:
			Client._counter += 1
			n = Client._counter
		return ("A%06d" % n).encode()

	def _send(self, data):
		self.sock.sendall(data)

	def _read_exact(self, n):
		out = bytearray()
		while len(out) < n:
			chunk = self.rf.read(n - len(out))
			if not chunk:
				raise IMAPError("eof while reading literal (%d/%d)" % (len(out), n))
			out += chunk
		return bytes(out)

	def _read_logical(self):
		"""One logical response line, splicing in any inline literals."""
		data = bytearray()
		while True:
			line = self.rf.readline()
			if not line:
				raise IMAPError("eof")
			data += line
			m = re.search(rb"\{(\d+)\}\r\n$", line)
			if m:
				data += self._read_exact(int(m.group(1)))
				continue
			break
		return bytes(data)

	def _is_tagged(self, line, tag):
		# exact tag match, guarding against prefix collisions (A000010 vs A000001)
		return line[:len(tag)] == tag and line[len(tag):len(tag) + 1] == b" "

	def cmd(self, line, raise_on_no=True):
		"""Send 'TAG line'; return (status, tagged_text, untagged_logical_lines)."""
		tag = self._tag()
		if isinstance(line, str):
			line = line.encode()
		self._send(tag + b" " + line + CRLF)
		untagged = []
		while True:
			resp = self._read_logical()
			if self._is_tagged(resp, tag):
				parts = resp[len(tag) + 1:].split(b" ", 1)
				status = parts[0].decode()
				text = parts[1].decode("latin-1", "replace") if len(parts) > 1 else ""
				if status != "OK" and raise_on_no:
					raise IMAPError("%s -> %s %s" % (line.decode("latin-1"), status, text.strip()))
				return status, text, untagged
			untagged.append(resp)

	def append(self, folder, msg_bytes, flags=""):
		tag = self._tag()
		fl = ("(%s) " % flags) if flags else ""
		self._send(('%s APPEND %s %s{%d}\r\n' % (tag.decode(), _q(folder), fl, len(msg_bytes))).encode())
		# wait for the '+' go-ahead, tolerating any untagged lines / early reject
		while True:
			line = self._read_logical()
			if line.startswith(b"+"):
				break
			if self._is_tagged(line, tag):
				raise IMAPError("APPEND rejected: %r" % line)
			# else: untagged status update, ignore
		self._send(msg_bytes + CRLF)
		while True:
			resp = self._read_logical()
			if self._is_tagged(resp, tag):
				status = resp[len(tag) + 1:].split(b" ", 1)[0].decode()
				if status != "OK":
					raise IMAPError("APPEND -> %r" % resp)
				return status

	def fetch_body_items(self, seqset, want=b"BODY[2]", fetch_item="BODY.PEEK[2]"):
		"""Stream-hash the single requested body item per message (low memory).

		Returns (status, {seq: (size, sha256hex)} | {seq: None for NIL}).
		Handles the item value as a literal, NIL, or quoted-string/atom.
		"""
		tag = self._tag()
		self._send(("%s FETCH %s %s\r\n" % (tag.decode(), seqset, fetch_item)).encode())
		results = {}
		while True:
			line = self.rf.readline()
			if not line:
				raise IMAPError("eof during fetch")
			if self._is_tagged(line, tag):
				return line[len(tag) + 1:].split(b" ", 1)[0].decode(), results
			m = re.search(rb"\{(\d+)\}\r\n$", line)
			sm = re.search(rb"\* (\d+) FETCH", line)
			if m:
				n = int(m.group(1))
				head = line[:m.start()]
				h = hashlib.sha256()
				rem = n
				while rem > 0:
					chunk = self.rf.read(min(262144, rem))
					if not chunk:
						raise IMAPError("eof in literal")
					h.update(chunk)
					rem -= len(chunk)
				if sm and want in head:
					results[int(sm.group(1))] = (n, h.hexdigest())
				self._drain_after_literal()
				continue
			if sm and want in line:
				if b"NIL" in line:
					results[int(sm.group(1))] = None
				else:
					qm = re.search(re.escape(want) + rb' "((?:[^"\\]|\\.)*)"', line)
					if qm:
						v = qm.group(1)
						results[int(sm.group(1))] = (len(v), hashlib.sha256(v).hexdigest())
		# unreachable

	def fetch_one(self, seq, fetch_item, want):
		"""Fetch a single small body item, return (status, bytes|None)."""
		tag = self._tag()
		self._send(("%s FETCH %s %s\r\n" % (tag.decode(), seq, fetch_item)).encode())
		val = None
		while True:
			line = self.rf.readline()
			if not line:
				raise IMAPError("eof")
			if self._is_tagged(line, tag):
				return line[len(tag) + 1:].split(b" ", 1)[0].decode(), val
			m = re.search(rb"\{(\d+)\}\r\n$", line)
			if m:
				data = self._read_exact(int(m.group(1)))
				if want in line[:m.start()]:
					val = data
				self._drain_after_literal()
				continue
			if want in line and b"* " in line[:8] and b"FETCH" in line:
				if b"NIL" in line:
					val = None
				else:
					qm = re.search(re.escape(want) + rb' "((?:[^"\\]|\\.)*)"', line)
					if qm:
						val = qm.group(1)

	def _drain_after_literal(self):
		while True:
			line = self.rf.readline()
			if not line:
				raise IMAPError("eof after literal")
			m = re.search(rb"\{(\d+)\}\r\n$", line)
			if m:
				self._read_exact(int(m.group(1)))
				continue
			return

	def noop_untagged(self):
		return self.cmd("NOOP")[2]

	def logout(self):
		try:
			self.cmd("LOGOUT", raise_on_no=False)
		except Exception:
			pass
		try:
			self.sock.close()
		except Exception:
			pass


def _q(name):
	if re.match(r'^[A-Za-z0-9_./@-]+$', name):
		return name
	return '"' + name.replace('\\', '\\\\').replace('"', '\\"') + '"'


def folder_messages(c, name):
	"""Return message count, or None if the folder does not exist."""
	st, txt, u = c.cmd("STATUS %s (MESSAGES)" % _q(name), raise_on_no=False)
	if st != "OK":
		return None
	for x in u:
		m = re.search(rb"MESSAGES (\d+)", x)
		if m:
			return int(m.group(1))
	return 0


def guard_create(c, name, force):
	"""Abort if 'name' already exists non-empty (protect real data), else
	(re)create it empty."""
	n = folder_messages(c, name)
	if n and n > 0 and not force:
		raise SystemExit("ABORT: folder %r exists with %d messages; refusing to "
		                 "wipe it. Use --force or a different --folder." % (name, n))
	c.cmd("DELETE %s" % _q(name), raise_on_no=False)
	c.cmd("CREATE %s" % _q(name))


# ---------------------------------------------------------------------------
# Test-message construction
# ---------------------------------------------------------------------------
def make_nested_message(idx, inner_kib):
	"""multipart/mixed: [1] text/plain cover, [2] message/rfc822 (large).

	The encapsulated message starts with a unique X-Inner-Marker header so a
	ranged partial fetch of BODY[2] gives an independent correctness anchor.
	"""
	rnd = random.Random(1000 + idx)
	target = inner_kib * 1024
	chunk = ("msg%04d " % idx) + "".join(
		rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789 ") for _ in range(56))
	body_lines = []
	total = 0
	while total < target: # linear (scalar accumulator)
		body_lines.append(chunk)
		total += len(chunk) + 2
	inner = (
		"X-Inner-Marker: GXINNER-%d\r\n"
		"From: inner-%d@test.invalid\r\n"
		"To: rcpt@test.invalid\r\n"
		"Subject: inner message %d\r\n"
		"Message-ID: <inner-%d@test.invalid>\r\n"
		"MIME-Version: 1.0\r\n"
		"Content-Type: text/plain; charset=us-ascii\r\n"
		"\r\n" % (idx, idx, idx, idx)
	) + "\r\n".join(body_lines) + "\r\n"
	outer = (
		"From: outer-%d@test.invalid\r\n"
		"To: rcpt@test.invalid\r\n"
		"Subject: GXVALIDATE nested %d\r\n"
		"Message-ID: <outer-%d@test.invalid>\r\n"
		"MIME-Version: 1.0\r\n"
		"Content-Type: multipart/mixed; boundary=\"GXB0UND\"\r\n"
		"\r\n"
		"--GXB0UND\r\n"
		"Content-Type: text/plain; charset=us-ascii\r\n"
		"\r\n"
		"cover text for message %d\r\n"
		"--GXB0UND\r\n"
		"Content-Type: message/rfc822\r\n"
		"\r\n" % (idx, idx, idx, idx)
	) + inner + "\r\n--GXB0UND--\r\n"
	return outer.encode("ascii")


def make_small_message(idx):
	return (
		"From: s-%d@test.invalid\r\n"
		"To: rcpt@test.invalid\r\n"
		"Subject: GXVALIDATE small %d\r\n"
		"MIME-Version: 1.0\r\n"
		"Content-Type: text/plain; charset=us-ascii\r\n"
		"\r\n"
		"small body %d\r\n" % (idx, idx, idx)
	).encode("ascii")


# ---------------------------------------------------------------------------
# Filesystem observer for tmp/imap.rfc822 (server-side, optional)
# ---------------------------------------------------------------------------
class TmpWatcher(threading.Thread):
	"""Tracks filenames that appear in tmpdir relative to a baseline snapshot."""
	def __init__(self, tmpdir, interval=0.0008):
		super().__init__(daemon=True)
		self.tmpdir = tmpdir
		self.interval = interval
		self.stop_flag = threading.Event()
		self.baseline = set(self._ls())
		self.new_names = set() # union of NEW names ever observed
		self.max_new = 0 # peak instantaneous count of new files

	def _ls(self):
		try:
			return os.listdir(self.tmpdir)
		except OSError:
			return []

	def run(self):
		while not self.stop_flag.is_set():
			cur = set(self._ls()) - self.baseline
			if cur:
				self.new_names |= cur
				self.max_new = max(self.max_new, len(cur))
			time.sleep(self.interval)

	def stop(self):
		self.stop_flag.set()
		self.join(timeout=2)


def rss_kib(pid):
	try:
		with open("/proc/%s/status" % pid) as f:
			for ln in f:
				if ln.startswith("VmRSS:"):
					return int(ln.split()[1])
	except OSError:
		return None
	return None


# ---------------------------------------------------------------------------
class Report:
	def __init__(self):
		self.rows = []
	def add(self, name, ok, detail=""):
		self.rows.append((name, bool(ok), detail))
		print("  [%s] %-28s %s" % ("PASS" if ok else "FAIL", name, detail))
		sys.stdout.flush()
	def ok(self):
		return all(r[1] for r in self.rows)
	def summary(self):
		return sum(1 for r in self.rows if r[1]), len(self.rows)


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------
def setup(cfg, c):
	guard_create(c, cfg.folder, cfg.force)
	c.cmd("SELECT %s" % _q(cfg.folder))
	for i in range(cfg.nmsgs):
		c.append(cfg.folder, make_nested_message(i, cfg.inner_kib))
	for i in range(2):
		c.append(cfg.folder, make_small_message(i))
	return folder_messages(c, cfg.folder) or 0


def teardown(cfg, c):
	c.cmd("CLOSE", raise_on_no=False)
	for f in (cfg.folder, cfg.folder + "_FUNC", cfg.folder + "_MV"):
		c.cmd("DELETE %s" % _q(f), raise_on_no=False)


def phase_func(cfg, rep):
	ff, dest = cfg.folder + "_FUNC", cfg.folder + "_MV"
	c = Client(cfg).login_select()
	try:
		st, txt, u = c.cmd("CAPABILITY")
		capline = b" ".join(u).decode("latin-1")  # caps are on the untagged "* CAPABILITY" line
		for tok in ("IMAP4rev1", "IDLE", "MOVE", "ESEARCH", "SEARCHRES",
		            "LIST-EXTENDED", "NAMESPACE", "IMAP4rev2"):
			rep.add("FUNC cap %s" % tok, tok in capline)
		guard_create(c, ff, cfg.force)
		guard_create(c, dest, cfg.force)
		c.append(ff, make_nested_message(9001, 4))
		c.append(ff, make_small_message(1))
		c.append(ff, make_small_message(2))
		c.cmd("SELECT %s" % _q(ff))

		st, txt, u = c.cmd("FETCH 1 (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)")
		rep.add("FUNC fetch envelope", st == "OK" and any(b"ENVELOPE" in x for x in u))
		st, txt, u = c.cmd("FETCH 1 BODYSTRUCTURE")
		rep.add("FUNC bodystructure nested", st == "OK"
		        and any(b"rfc822" in x.lower() for x in u))
		for item, want in (("BODY.PEEK[2]", b"BODY[2]"), ("BODY.PEEK[2.1]", b"BODY[2.1]"),
		                   ("BODY.PEEK[2.TEXT]", b"BODY[2.TEXT]"), ("BODY.PEEK[2.HEADER]", b"BODY[2.HEADER]")):
			st, res = c.fetch_body_items("1", want=want, fetch_item=item)
			v = res.get(1)
			rep.add("FUNC %s" % item, st == "OK" and v is not None and v[0] > 0,
			        "" if v else "NIL/missing")

		st, txt, u = c.cmd("SEARCH ALL")
		rep.add("FUNC search all", st == "OK" and any(b"SEARCH" in x for x in u))
		st, txt, u = c.cmd("SEARCH RETURN (COUNT MIN MAX) ALL")
		rep.add("FUNC esearch", st == "OK" and any(b"ESEARCH" in x for x in u))
		c.cmd("SEARCH RETURN (SAVE) ALL")
		st, txt, u = c.cmd("FETCH $ (UID)")
		rep.add("FUNC searchres $", st == "OK" and any(b"FETCH" in x for x in u))

		c.cmd("STORE 1 +FLAGS (GXKW1)")
		st, txt, u = c.cmd("FETCH 1 FLAGS")
		rep.add("FUNC store keyword", st == "OK" and any(b"GXKW1" in x for x in u))
		st, txt, u = c.cmd("SEARCH KEYWORD GXKW1")
		rep.add("FUNC search keyword", st == "OK" and any(re.search(rb"\* SEARCH\b.*\b1\b", x) for x in u))

		before = folder_messages(c, ff)
		st, _, _ = c.cmd("UID MOVE 3 %s" % _q(dest), raise_on_no=False)
		after = folder_messages(c, ff)
		dn = folder_messages(c, dest)
		rep.add("FUNC uid move", st == "OK" and after == before - 1 and dn == 1,
		        "src %s->%s dest=%s" % (before, after, dn))

		st, txt, u = c.cmd('LIST "" "*" RETURN (CHILDREN)')
		rep.add("FUNC list-extended", st == "OK" and any(b"LIST" in x for x in u))
		st, txt, u = c.cmd("NAMESPACE")
		rep.add("FUNC namespace", st == "OK" and any(b"NAMESPACE" in x for x in u))

		st, txt, u = c.cmd("ENABLE IMAP4rev2")
		rep.add("FUNC enable rev2", st == "OK" and any(b"ENABLED" in x for x in u))
		c.cmd("CLOSE", raise_on_no=False)
		st, txt, u = c.cmd("SELECT %s" % _q(ff))
		rep.add("FUNC rev2 no RECENT", st == "OK" and not any(re.search(rb"\d+ RECENT", x) for x in u))
	finally:
		try:
			c.cmd("CLOSE", raise_on_no=False)
			c.cmd("DELETE %s" % _q(ff), raise_on_no=False)
			c.cmd("DELETE %s" % _q(dest), raise_on_no=False)
		except Exception:
			pass
		c.logout()


def phase_r1(cfg, rep, watcher=None):
	g = Client(cfg).login_select(cfg.folder)
	st, golden = g.fetch_body_items("1:%d" % cfg.nmsgs)
	# independent anchor: ranged partial fetch of the marker bytes we APPENDed
	st_a, head = g.fetch_one("1", "BODY.PEEK[2]<0.40>", b"BODY[2]")
	g.logout()

	total = sum(v[0] for v in golden.values() if v)
	nils = sum(1 for v in golden.values() if v is None)
	if not golden or nils:
		rep.add("R1 golden baseline", False, "%d items, %d NIL" % (len(golden), nils))
		return
	rep.add("R1 golden baseline", True, "%d parts, %.1f MiB total" % (len(golden), total / 1048576.0))
	rep.add("R1 over-budget precondition", total > BUDGET * 11 // 10,
	        "%.1f MiB vs 64 MiB budget (need eviction; raise --nmsgs/--inner-kib if FAIL)" % (total / 1048576.0))
	rep.add("R1 anchor (independent + partial fetch)",
	        head is not None and head.startswith(b"X-Inner-Marker: GXINNER-0"),
	        "got %r" % (head[:28] if head else None))

	counters = {"fetches": 0, "nil": 0, "mismatch": 0}
	errors = [] # appended lock-free; only read after join()
	clock = threading.Lock()

	def worker(wid):
		try:
			c = Client(cfg).login_select(cfg.folder)
			for _ in range(cfg.r1_rounds):
				st, res = c.fetch_body_items("1:%d" % cfg.nmsgs)
				with clock:
					counters["fetches"] += 1
				for seq, exp in golden.items():
					got = res.get(seq, "missing")
					if got is None:
						with clock: counters["nil"] += 1
						errors.append("w%d seq%d NIL" % (wid, seq))
					elif got != exp:
						with clock: counters["mismatch"] += 1
						errors.append("w%d seq%d divergent" % (wid, seq))
			c.logout()
		except Exception as e:
			errors.append("w%d exc %s" % (wid, e))

	ts = [threading.Thread(target=worker, args=(i,)) for i in range(cfg.r1_conns)]
	for t in ts: t.start()
	for t in ts: t.join()

	exc = [e for e in errors if "exc" in e]
	rep.add("R1 no cross-conn corruption",
		    counters["nil"] == 0 and counters["mismatch"] == 0 and not exc,
		    "%d conns x %d rounds = %d fetches; NIL=%d divergent=%d exc=%d"
		    % (cfg.r1_conns, cfg.r1_rounds, counters["fetches"], counters["nil"],
		       counters["mismatch"], len(exc)))
	if errors:
		print("       first issues:", errors[:5])

	if watcher is not None:
		bad = [n for n in watcher.new_names if not re.match(r"^\d+_", n)]
		serials = set(n.split("_", 1)[0] for n in watcher.new_names if re.match(r"^\d+_", n))
		rep.add("R1 eviction actually occurred", len(watcher.new_names) > 0,
		        "%d backing files observed during storm" % len(watcher.new_names))
		rep.add("R1-iso per-conn isolation",
		        len(watcher.new_names) > 0 and not bad and len(serials) >= 2,
		        "%d distinct serial prefixes, %d non-conforming names"
		        % (len(serials), len(bad)))


def phase_r5(cfg, rep, tmpdir):
	c = Client(cfg).login_select(cfg.folder)
	# under budget: many single-message rfc822 fetches must write nothing new
	w = TmpWatcher(tmpdir); w.start()
	for _ in range(cfg.r5_iters):
		c.fetch_body_items("1")
	time.sleep(0.05); w.stop()
	rep.add("R5 under-budget: no disk writes", len(w.new_names) == 0,
	        "%d small fetches, NEW files in tmp/imap.rfc822 = %d (expect 0)"
	        % (cfg.r5_iters, len(w.new_names)))
	# over budget: wide fetch must create files then clean them up
	w2 = TmpWatcher(tmpdir); w2.start()
	c.fetch_body_items("1:%d" % cfg.nmsgs)
	time.sleep(0.05); w2.stop()
	rep.add("R5 over-budget: mechanism works", len(w2.new_names) > 0,
	        "wide fetch created %d backing files (expect >0)" % len(w2.new_names))
	time.sleep(0.2)
	left = len(os.listdir(tmpdir)) if os.path.isdir(tmpdir) else -1
	rep.add("R5 scratch cleaned up", left == 0, "files left after fetch = %d (expect 0)" % left)
	c.logout()


def phase_r2(cfg, rep):
	a = Client(cfg).login_select(cfg.folder)
	b = Client(cfg).login_select(cfg.folder)
	seen = set()
	stop = threading.Event()

	def poller():
		while not stop.is_set():
			try:
				u = a.noop_untagged()
			except Exception:
				break
			for x in u:
				for mm in re.finditer(rb"GXR2R\d+", x):
					seen.add(mm.group(0).decode())
			time.sleep(0.01)

	th = threading.Thread(target=poller); th.start()
	sent = []
	for rnd in range(cfg.r2_rounds): # rapid, concurrent with the poller
		kw = "GXR2R%d" % rnd
		sent.append(kw)
		b.cmd("STORE 1 +FLAGS (%s)" % kw)
	deadline = time.monotonic() + 4.0
	while time.monotonic() < deadline and not set(sent).issubset(seen):
		time.sleep(0.05)
	stop.set(); th.join(timeout=2)
	missed = [k for k in sent if k not in seen]
	rep.add("R2 async notify liveness", not missed,
	        "%d changes, missed=%d (liveness only -- not a discriminating race test)"
	        % (len(sent), len(missed)))
	a.logout(); b.logout()


def phase_load(cfg, rep, tmpdir, pid):
	deadline = time.monotonic() + cfg.load_secs
	counters = {"ops": 0, "err": 0, "nil": 0, "reconn": 0, "fatal": 0}
	clock = threading.Lock()
	rss = []

	def worker(wid):
		c = None
		reconn = 0
		rnd = random.Random(wid)
		try:
			c = Client(cfg).login_select(cfg.folder)
			while time.monotonic() < deadline:
				try:
					op = rnd.randint(0, 4)
					if op == 0:
						lo = rnd.randint(1, cfg.nmsgs)
						_, res = c.fetch_body_items("%d:%d" % (lo, cfg.nmsgs))
						nn = sum(1 for v in res.values() if v is None)
						with clock:
							counters["nil"] += nn
					elif op == 1:
						c.cmd("SEARCH SUBJECT GXVALIDATE")
					elif op == 2:
						c.cmd("FETCH 1:%d (FLAGS RFC822.SIZE)" % cfg.nmsgs)
					elif op == 3:
						c.cmd("STORE %d +FLAGS (GXLOAD%d)" % (rnd.randint(1, cfg.nmsgs), wid))
					else:
						c.cmd("FETCH 1 BODYSTRUCTURE")
					with clock:
						counters["ops"] += 1
				except Exception:
					with clock:
						counters["err"] += 1
					if reconn >= cfg.load_reconnects:
						with clock: counters["fatal"] += 1
						break
					reconn += 1
					try: c.logout()
					except Exception: pass
					try:
						c = Client(cfg).login_select(cfg.folder)
					except Exception:
						with clock: counters["fatal"] += 1
						break
		finally:
			with clock:
				counters["reconn"] += reconn
			if c:
				c.logout()

	base = rss_kib(pid) if pid else None
	ts = [threading.Thread(target=worker, args=(i,)) for i in range(cfg.load_conns)]
	for t in ts: t.start()
	while any(t.is_alive() for t in ts):
		if pid:
			r = rss_kib(pid)
			if r: rss.append(r)
		time.sleep(1.0)
	for t in ts: t.join()

	secs = max(0.001, cfg.load_secs)
	rep.add("LOAD throughput", counters["ops"] >= cfg.load_conns,
	        "%d ops in %ds = %.0f ops/s across %d conns (reconnects=%d)"
	        % (counters["ops"], cfg.load_secs, counters["ops"] / secs, cfg.load_conns, counters["reconn"]))
	rep.add("LOAD no errors/disconnects", counters["err"] == 0 and counters["fatal"] == 0,
	        "errors=%d fatal=%d" % (counters["err"], counters["fatal"]))
	rep.add("LOAD no NIL bodies", counters["nil"] == 0, "NIL bodies under load = %d" % counters["nil"])
	if pid and rss:
		peak, final = max(rss), rss[-1]
		grew = base and final > base * 4 and final - base > 512 * 1024
		rep.add("LOAD memory bounded", not grew,
		        "baseline=%.0f peak=%.0f final=%.0f MiB"
		        % ((base or 0) / 1024.0, peak / 1024.0, final / 1024.0))
	if tmpdir:
		time.sleep(0.3)
		left = len(os.listdir(tmpdir)) if os.path.isdir(tmpdir) else -1
		rep.add("LOAD no scratch leak", left == 0, "tmp/imap.rfc822 files after load = %d" % left)


# ---------------------------------------------------------------------------
def main():
	ap = argparse.ArgumentParser(description="gromox-imap concurrency/functional validator")
	ap.add_argument("--host", required=True)
	ap.add_argument("--port", type=int, default=0)
	ap.add_argument("--user", required=True)
	ap.add_argument("--pass", dest="password", required=True)
	ap.add_argument("--no-ssl", action="store_true")
	ap.add_argument("--timeout", type=float, default=120.0)
	ap.add_argument("--folder", default="GXVALIDATE")
	ap.add_argument("--maildir", default="", help="server-side maildir (enables R1-iso/R5 fs checks)")
	ap.add_argument("--pid", default="", help="imap pid (RSS monitoring during LOAD)")
	ap.add_argument("--nmsgs", type=int, default=24)
	ap.add_argument("--inner-kib", type=int, default=4096)
	ap.add_argument("--r1-conns", type=int, default=12)
	ap.add_argument("--r1-rounds", type=int, default=6)
	ap.add_argument("--r5-iters", type=int, default=60)
	ap.add_argument("--r2-rounds", type=int, default=40)
	ap.add_argument("--load-conns", type=int, default=80)
	ap.add_argument("--load-secs", type=int, default=45)
	ap.add_argument("--load-reconnects", type=int, default=3)
	ap.add_argument("--keep", action="store_true")
	ap.add_argument("--force", action="store_true", help="wipe a pre-existing non-empty test folder")
	ap.add_argument("--only", default="", help="subset: func,r1,r5,r2,load")
	cfg = ap.parse_args()
	cfg.ssl = not cfg.no_ssl
	if cfg.port == 0:
		cfg.port = 993 if cfg.ssl else 143
	tmpdir = os.path.join(cfg.maildir, "tmp", "imap.rfc822") if cfg.maildir else ""
	only = set(x.strip() for x in cfg.only.split(",") if x.strip())
	run = lambda n: (not only) or (n in only)

	print("== gromox-imap validation ==")
	print("target %s:%d ssl=%s user=%s folder=%s" % (cfg.host, cfg.port, cfg.ssl, cfg.user, cfg.folder))
	print("fs checks: %s | rss pid: %s" % (tmpdir or "(off)", cfg.pid or "(off)"))
	rep = Report()

	admin = Client(cfg).login_select()
	print("-- setup --")
	try:
		n = setup(cfg, admin)
		print("   test folder populated: %d messages (%.0f MiB)" % (n, cfg.nmsgs * cfg.inner_kib / 1024.0))
		if run("func"):
			print("-- FUNC --"); phase_func(cfg, rep)
		if run("r1"):
			print("-- R1: cross-connection rfc822 delete race --")
			w = None
			if tmpdir and os.path.isdir(tmpdir):
				w = TmpWatcher(tmpdir, interval=0.001); w.start()
			phase_r1(cfg, rep, watcher=w)
			if w: w.stop()
		if run("r5"):
			if tmpdir and os.path.isdir(tmpdir):
				print("-- R5: persist-on-evict latency --"); phase_r5(cfg, rep, tmpdir)
			else:
				print("-- R5: skipped (needs --maildir on the server) --")
		if run("r2"):
			print("-- R2: async notification liveness --"); phase_r2(cfg, rep)
		if run("load"):
			print("-- LOAD: concurrent stress --")
			phase_load(cfg, rep, tmpdir if (tmpdir and os.path.isdir(tmpdir)) else "", cfg.pid)
	finally:
		print("-- teardown --")
		if not cfg.keep:
			teardown(cfg, admin)
		admin.logout()

	npass, ntot = rep.summary()
	print("\n== RESULT: %d/%d checks passed ==" % (npass, ntot))
	sys.exit(0 if rep.ok() else 1)


if __name__ == "__main__":
	main()
