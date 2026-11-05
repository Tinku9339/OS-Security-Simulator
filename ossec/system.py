import secrets, time
from .auth import UserStore
from .access import FileObj, check, safe_path, AccessError, READ, WRITE
from .audit import AuditLog
from . import vault

ROOT = "/vault"

class SecureSystem:
    def __init__(self, clock=time.time, iterations=200_000):
        self.users = UserStore(clock, iterations)
        self.audit = AuditLog(clock)
        self.sessions, self.meta, self.blobs = {}, {}, {}
        self.keys = {}  # per-file passphrase held only for the demo owner-keyring

    def login(self, name, password, otp=None):
        ok, why = self.users.authenticate(name, password, otp)
        self.audit.log(name, "login", "-", ok, why)
        if not ok: return None
        tok = secrets.token_hex(16); self.sessions[tok] = name; return tok

    def logout(self, tok): self.sessions.pop(tok, None)

    def _who(self, tok):
        n = self.sessions.get(tok)
        if n is None: raise AccessError("not authenticated")
        return n, self.users.users[n]

    def _gate(self, tok, action, obj, path):
        n, u = self._who(tok)
        ok, why = check(u, n, obj, action)
        self.audit.log(n, action, path, ok, why)
        if not ok: raise AccessError(f"{action} denied on {path}: {why}")
        return n, u

    def create(self, tok, path, data, passphrase, mode=0o640, level=1, group="staff"):
        n, u = self._who(tok)
        try: p = safe_path(ROOT, path)
        except AccessError as e:
            self.audit.log(n, "create", path, False, str(e)); raise
        if p in self.meta: raise FileExistsError(p)
        self.meta[p] = FileObj(n, group, mode, level)
        self.blobs[p] = vault.encrypt(passphrase, data, p.encode())
        self.audit.log(n, "create", p, True, "encrypted at rest")
        return p

    def read(self, tok, path, passphrase):
        self._who(tok)  # authenticate before revealing whether the file exists
        p = safe_path(ROOT, path)
        if p not in self.meta: raise FileNotFoundError(p)
        self._gate(tok, READ, self.meta[p], p)
        return vault.decrypt(passphrase, self.blobs[p], p.encode())

    def write(self, tok, path, data, passphrase):
        self._who(tok)
        p = safe_path(ROOT, path)
        if p not in self.meta: raise FileNotFoundError(p)
        self._gate(tok, WRITE, self.meta[p], p)
        self.blobs[p] = vault.encrypt(passphrase, data, p.encode())

    def chmod(self, tok, path, mode):
        n, u = self._who(tok); p = safe_path(ROOT, path)
        if u["role"] != "admin" and n != self.meta[p].owner:
            self.audit.log(n, "chmod", p, False, "not owner"); raise AccessError("only owner/admin may chmod")
        self.meta[p].mode = mode; self.audit.log(n, "chmod", p, True, oct(mode))
