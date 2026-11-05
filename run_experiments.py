import json, time, random, hashlib, posixpath
from ossec.auth import UserStore, InsecureUserStore, hash_password
from ossec.access import safe_path, AccessError, FileObj, check
from ossec import vault
from ossec.audit import AuditLog
from ossec.system import SecureSystem

random.seed(7)
R = {}
GOOD = "Str0ng!Passw0rd"

# E1 - leaked credential store vs dictionary attack
words = [f"pass{i}" for i in range(499)] + ["Summer2024"]
random.shuffle(words)
ins = InsecureUserStore(); ins.register("u1", "Summer2024")
t = time.perf_counter(); found = any(w == ins.users["u1"]["password"] for w in words); t_plain = time.perf_counter() - t
salt, dk = hash_password("Summer2024", iterations=200_000)
t = time.perf_counter(); tries = 0
for w in words:
    tries += 1
    if hash_password(w, salt)[1] == dk: break
t_hash = time.perf_counter() - t
t = time.perf_counter(); hash_password("x", salt); per_guess = time.perf_counter() - t
R["E1_dictionary_attack_on_leaked_store"] = dict(wordlist=len(words), plaintext_found=found, plaintext_seconds=round(t_plain, 6),
    pbkdf2_guesses_until_found=tries, pbkdf2_seconds=round(t_hash, 2), pbkdf2_seconds_per_guess=round(per_guess, 4),
    slowdown_per_guess_vs_sha256=None)
t = time.perf_counter()
for _ in range(2000): hashlib.sha256(b"x").digest()
fast = (time.perf_counter() - t) / 2000
R["E1_dictionary_attack_on_leaked_store"]["slowdown_per_guess_vs_sha256"] = round(per_guess / fast)

# E2 - online brute force: 1000 guesses
ins = InsecureUserStore(); ins.register("admin", "Summer2024")
pw = [f"guess{i}" for i in range(599)] + ["Summer2024"] + [f"guess{i}" for i in range(600, 1000)]
ins_ok = next((i + 1 for i, g in enumerate(pw) if ins.authenticate("admin", g)[0]), None)
clk = [0.0]; sec = UserStore(lambda: clk[0], iterations=1000); sec.register("admin", GOOD)
real = ["Summer2024"]; attempts_processed = 0; locked = 0
guesses = [f"guess{i}" for i in range(1000)]
for g in guesses:
    ok, why = sec.authenticate("admin", g); clk[0] += 1
    if why == "account locked": locked += 1
    else: attempts_processed += 1
R["E2_online_bruteforce_1000_guesses_1s_apart"] = dict(insecure_guess_number_that_succeeds=ins_ok,
    secure_guesses_evaluated=attempts_processed, secure_guesses_rejected_by_lockout=locked,
    lockout_policy="3 failures -> 300 s lock")

# E3 - access control matrix
s = SecureSystem(lambda: 0.0, iterations=1000)
s.users.register("alice", GOOD, "staff", 1, ["staff"]); s.users.register("bob", GOOD, "staff", 1, ["staff"])
s.users.register("eve", GOOD, "guest", 0, ["guest"]); s.users.register("carol", GOOD, "staff", 2, ["staff"])
s.users.register("root", GOOD, "admin", 3, ["staff"])
ta = s.login("alice", GOOD)
s.create(ta, "report.txt", b"quarterly numbers", "k", 0o640, 1); s.create(ta, "secret.txt", b"classified", "k", 0o640, 2)
s.create(ta, "private.txt", b"mine", "k", 0o600, 1)
s.meta["/vault/report.txt"].acl["eve"] = {"r"}
tok = {u: s.login(u, GOOD) for u in ["alice", "bob", "eve", "carol", "root"]}
rows = []; allowed = denied = 0
for u in tok:
    for f in ["report.txt", "secret.txt", "private.txt"]:
        for a in ["read", "write"]:
            try:
                (s.read(tok[u], f, "k") if a == "read" else s.write(tok[u], f, b"upd", "k")); res = "ALLOW"; allowed += 1
            except PermissionError: res = "DENY"; denied += 1
            rows.append((u, f, a, res))
R["E3_access_matrix"] = dict(requests=len(rows), allowed=allowed, denied=denied, insecure_baseline_allowed=len(rows),
    table={f"{u}|{f}|{a}": r for u, f, a, r in rows})

# E4 - path traversal
payloads = ["../etc/passwd", "../../etc/shadow", "docs/../../secret", "/../../root/.ssh/id_rsa", "a/./../../b", "ok/file.txt", "docs/report.txt", "a\x00.txt"]
naive = lambda p: posixpath.normpath(posixpath.join("/vault", p))
out = []
for p in payloads:
    n = naive(p); esc_naive = not n.startswith("/vault/")
    try: safe_path("/vault", p); blocked = False
    except AccessError: blocked = True
    out.append(dict(payload=p.replace("\x00", "\\x00"), naive_resolves_to=n, naive_escapes_root=esc_naive, secure_blocked=blocked))
R["E4_path_traversal"] = dict(payloads=len(payloads), naive_escapes=sum(o["naive_escapes_root"] for o in out),
    secure_blocked=sum(o["secure_blocked"] for o in out), detail=out)

# E5 - encryption integrity and overhead
blob = vault.encrypt("pw", b"The quick brown fox" * 5)
detected = 0; N = 1000
for _ in range(N):
    b = bytearray(blob); i = random.randrange(4, len(b)); b[i] ^= 1 << random.randrange(8)
    try: vault.decrypt("pw", bytes(b))
    except ValueError: detected += 1
sizes = {}
for n in [1024, 102400, 1048576]:
    d = random.randbytes(n); t = time.perf_counter(); e = vault.encrypt("pw", d); te = time.perf_counter() - t
    t = time.perf_counter(); vault.decrypt("pw", e); td = time.perf_counter() - t
    sizes[str(n)] = dict(overhead_bytes=len(e) - n, encrypt_ms=round(te * 1000, 1), decrypt_ms=round(td * 1000, 1))
R["E5_encryption"] = dict(bitflip_trials=N, detected=detected, sizes=sizes,
    same_plaintext_twice_identical_ciphertext=vault.encrypt("pw", b"x") == vault.encrypt("pw", b"x"))

# E6 - audit tamper
a = AuditLog(lambda: 1.0)
for i in range(100): a.log("u", "read", f"/f{i}", i % 3 != 0)
base = a.verify(); det = 0
for k in range(100):
    import copy; b = AuditLog(lambda: 1.0); b.entries = copy.deepcopy(a.entries); b.entries[k]["allowed"] = not b.entries[k]["allowed"]
    det += (not b.verify()[0])
R["E6_audit_log"] = dict(entries=100, untouched_valid=base[0], single_entry_edits=100, detected=det)

# E7 - PBKDF2 cost
cost = {}
for it in [1000, 10_000, 100_000, 200_000, 600_000]:
    t = time.perf_counter(); hash_password("pw", b"s" * 16, it); cost[str(it)] = round((time.perf_counter() - t) * 1000, 1)
R["E7_pbkdf2_cost_ms"] = cost
json.dump(R, open("results/experiment_results.json", "w"), indent=1)
print(json.dumps({k: (v if k not in ("E3_access_matrix", "E4_path_traversal") else {x: y for x, y in v.items() if x not in ("table", "detail")}) for k, v in R.items()}, indent=1))
for r in rows: print(r)
for o in out: print(o)
