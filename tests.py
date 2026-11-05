import unittest, base64
from ossec.auth import UserStore, InsecureUserStore, totp, password_policy_errors
from ossec.access import check, safe_path, FileObj, AccessError
from ossec import vault
from ossec.audit import AuditLog
from ossec.system import SecureSystem

class Clock:
    def __init__(s): s.t = 1_000_000.0
    def __call__(s): return s.t

GOOD = "Str0ng!Passw0rd"
def mk():
    c = Clock(); s = SecureSystem(c, iterations=1000)
    s.users.register("alice", GOOD, "staff", 1, ["staff"])
    s.users.register("bob", GOOD, "staff", 1, ["staff"])
    s.users.register("eve", GOOD, "guest", 0, ["guest"])
    s.users.register("root", GOOD, "admin", 3, ["staff"])
    s.users.register("carol", GOOD, "staff", 2, ["staff"])
    return s, c

class AuthTests(unittest.TestCase):
    def test_policy_rejects_weak(self): self.assertTrue(password_policy_errors("password"))
    def test_policy_accepts_strong(self): self.assertEqual(password_policy_errors(GOOD), [])
    def test_register_weak_raises(self):
        with self.assertRaises(ValueError): UserStore().register("x", "abc")
    def test_correct_and_wrong_password(self):
        s, _ = mk()
        self.assertTrue(s.users.authenticate("alice", GOOD)[0])
        self.assertFalse(s.users.authenticate("alice", "wrong")[0])
    def test_unknown_user(self):
        s, _ = mk(); self.assertFalse(s.users.authenticate("nobody", GOOD)[0])
    def test_salts_differ_for_same_password(self):
        s, _ = mk(); u = s.users.users
        self.assertNotEqual(u["alice"]["hash"], u["bob"]["hash"])
    def test_lockout_and_expiry(self):
        s, c = mk()
        for _ in range(3): s.users.authenticate("alice", "bad")
        self.assertEqual(s.users.authenticate("alice", GOOD), (False, "account locked"))
        c.t += 301
        self.assertTrue(s.users.authenticate("alice", GOOD)[0])
    def test_totp_rfc6238_vector(self):
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(totp(secret, t=59, digits=8), "94287082")
    def test_mfa_required(self):
        s, c = mk(); sec = s.users.register("dave", GOOD, mfa=True)
        self.assertFalse(s.users.authenticate("dave", GOOD)[0])
        self.assertFalse(s.users.authenticate("dave", GOOD, "000000")[0])
        self.assertTrue(s.users.authenticate("dave", GOOD, totp(sec, c.t))[0])
    def test_insecure_store_is_plaintext(self):
        i = InsecureUserStore(); i.register("a", "secret"); self.assertEqual(i.users["a"]["password"], "secret")

class AccessTests(unittest.TestCase):
    def setUp(self):
        self.o = FileObj("alice", "staff", 0o640, level=1)
        self.u = lambda role, clr, g: dict(role=role, clearance=clr, groups=set(g))
    def test_owner_rw(self):
        self.assertTrue(check(self.u("staff", 1, ["staff"]), "alice", self.o, "w")[0])
    def test_group_read_only(self):
        u = self.u("staff", 1, ["staff"])
        self.assertTrue(check(u, "bob", self.o, "r")[0]); self.assertFalse(check(u, "bob", self.o, "w")[0])
    def test_other_denied(self):
        self.assertFalse(check(self.u("guest", 1, ["guest"]), "eve", self.o, "r")[0])
    def test_mac_no_read_up(self):
        o = FileObj("alice", "staff", 0o644, level=2)
        self.assertFalse(check(self.u("staff", 1, ["staff"]), "bob", o, "r")[0])
    def test_acl_grant_and_deny(self):
        self.o.acl["eve"] = {"r"}; self.assertTrue(check(self.u("guest", 1, []), "eve", self.o, "r")[0])
        self.o.acl["bob"] = {"-r"}; self.assertFalse(check(self.u("staff", 1, ["staff"]), "bob", self.o, "r")[0])
    def test_admin_bypass_but_deny_acl_wins(self):
        a = self.u("admin", 3, []); self.assertTrue(check(a, "root", self.o, "r")[0])
        self.o.acl["root"] = {"-r"}; self.assertFalse(check(a, "root", self.o, "r")[0])
    def test_path_traversal_blocked(self):
        for bad in ["../etc/passwd", "a/../../etc/shadow", "/../x", "a\x00b"]:
            with self.assertRaises(AccessError): safe_path("/vault", bad)
    def test_path_inside_ok(self):
        self.assertEqual(safe_path("/vault", "docs/a.txt"), "/vault/docs/a.txt")

class CryptoTests(unittest.TestCase):
    def test_roundtrip(self): self.assertEqual(vault.decrypt("pw", vault.encrypt("pw", b"hello")), b"hello")
    def test_wrong_key(self):
        with self.assertRaises(ValueError): vault.decrypt("bad", vault.encrypt("pw", b"hello"))
    def test_tamper_detected(self):
        b = bytearray(vault.encrypt("pw", b"hello world")); b[-1] ^= 1
        with self.assertRaises(ValueError): vault.decrypt("pw", bytes(b))
    def test_unique_nonce_ciphertext(self): self.assertNotEqual(vault.encrypt("pw", b"x"), vault.encrypt("pw", b"x"))
    def test_aad_binding(self):
        b = vault.encrypt("pw", b"x", b"/vault/a")
        with self.assertRaises(ValueError): vault.decrypt("pw", b, b"/vault/b")
    def test_ciphertext_hides_plaintext(self): self.assertNotIn(b"TOPSECRET", vault.encrypt("pw", b"TOPSECRET data"))

class AuditTests(unittest.TestCase):
    def test_chain_valid_then_tampered(self):
        a = AuditLog(lambda: 1.0)
        for i in range(5): a.log("u", "read", f"/f{i}", True)
        self.assertEqual(a.verify(), (True, None))
        a.entries[2]["allowed"] = False
        self.assertEqual(a.verify(), (False, 2))
    def test_deleted_entry_detected(self):
        a = AuditLog(lambda: 1.0)
        for i in range(4): a.log("u", "r", str(i), True)
        del a.entries[1]; self.assertFalse(a.verify()[0])

class SystemTests(unittest.TestCase):
    def test_end_to_end(self):
        s, _ = mk(); ta = s.login("alice", GOOD)
        s.create(ta, "notes.txt", b"private", "k1")
        self.assertEqual(s.read(ta, "notes.txt", "k1"), b"private")
        tb = s.login("bob", GOOD); self.assertEqual(s.read(tb, "notes.txt", "k1"), b"private")
        with self.assertRaises(PermissionError): s.write(tb, "notes.txt", b"x", "k1")
        te = s.login("eve", GOOD)
        with self.assertRaises(PermissionError): s.read(te, "notes.txt", "k1")
    def test_requires_login(self):
        s, _ = mk()
        with self.assertRaises(PermissionError): s.read("fake", "x", "k")
    def test_chmod_only_owner(self):
        s, _ = mk(); ta = s.login("alice", GOOD); s.create(ta, "a", b"1", "k")
        tb = s.login("bob", GOOD)
        with self.assertRaises(PermissionError): s.chmod(tb, "a", 0o777)
        s.chmod(ta, "a", 0o600)
        with self.assertRaises(PermissionError): s.read(tb, "a", "k")
    def test_traversal_through_api(self):
        s, _ = mk(); ta = s.login("alice", GOOD)
        with self.assertRaises(PermissionError): s.create(ta, "../../etc/x", b"1", "k")
    def test_audit_records_denials(self):
        s, _ = mk(); ta = s.login("alice", GOOD); s.create(ta, "a", b"1", "k")
        te = s.login("eve", GOOD)
        try: s.read(te, "a", "k")
        except PermissionError: pass
        self.assertTrue(any(not e["allowed"] and e["user"] == "eve" for e in s.audit.entries))
        self.assertTrue(s.audit.verify()[0])
    def test_wrong_passphrase_fails_even_if_authorised(self):
        s, _ = mk(); ta = s.login("alice", GOOD); s.create(ta, "a", b"1", "k")
        with self.assertRaises(ValueError): s.read(ta, "a", "wrong")
    def test_logout_invalidates(self):
        s, _ = mk(); ta = s.login("alice", GOOD); s.logout(ta)
        with self.assertRaises(PermissionError): s.create(ta, "a", b"1", "k")

if __name__ == "__main__": unittest.main(verbosity=1)
