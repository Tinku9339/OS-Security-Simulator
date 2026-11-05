import hashlib, hmac, os, time, struct, base64, re

ITERATIONS = 200_000

def hash_password(password, salt=None, iterations=ITERATIONS):
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return salt, dk

def password_policy_errors(pw):
    errs = []
    if len(pw) < 10: errs.append("minimum 10 characters")
    if not re.search(r"[a-z]", pw): errs.append("needs lowercase letter")
    if not re.search(r"[A-Z]", pw): errs.append("needs uppercase letter")
    if not re.search(r"\d", pw): errs.append("needs digit")
    if not re.search(r"[^\w\s]", pw): errs.append("needs symbol")
    return errs

def totp(secret_b32, t=None, step=30, digits=6):
    """RFC 6238 time-based one-time password (HMAC-SHA1)."""
    key = base64.b32decode(secret_b32)
    counter = int((time.time() if t is None else t) // step)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o+4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

class UserStore:
    """Secure store: salted PBKDF2 hashes, lockout, optional TOTP second factor."""
    MAX_FAILS = 3
    LOCK_SECONDS = 300

    def __init__(self, clock=time.time, iterations=ITERATIONS):
        self.users, self.clock, self.iterations = {}, clock, iterations

    def register(self, name, password, role="staff", clearance=1, groups=(), mfa=False):
        if name in self.users: raise ValueError("user exists")
        errs = password_policy_errors(password)
        if errs: raise ValueError("weak password: " + ", ".join(errs))
        salt, dk = hash_password(password, iterations=self.iterations)
        secret = base64.b32encode(os.urandom(10)).decode() if mfa else None
        self.users[name] = dict(salt=salt, hash=dk, role=role, clearance=clearance,
                                groups=set(groups), fails=0, locked_until=0, totp=secret)
        return secret

    def authenticate(self, name, password, otp=None):
        u = self.users.get(name)
        if u is None:  # dummy work so unknown users cost the same time
            hash_password(password, b"0" * 16, self.iterations); return False, "invalid credentials"
        now = self.clock()
        if now < u["locked_until"]: return False, "account locked"
        _, dk = hash_password(password, u["salt"], self.iterations)
        ok = hmac.compare_digest(dk, u["hash"])
        if ok and u["totp"]:
            ok = otp is not None and hmac.compare_digest(otp, totp(u["totp"], now))
        if not ok:
            u["fails"] += 1
            if u["fails"] >= self.MAX_FAILS:
                u["locked_until"], u["fails"] = now + self.LOCK_SECONDS, 0
                return False, "account locked"
            return False, "invalid credentials"
        u["fails"] = 0
        return True, "ok"

class InsecureUserStore:
    """Deliberately vulnerable baseline: plaintext passwords, no lockout, no policy."""
    def __init__(self): self.users = {}
    def register(self, name, password, **kw): self.users[name] = {"password": password, **kw}
    def authenticate(self, name, password, otp=None):
        u = self.users.get(name)
        return (u is not None and u["password"] == password), "plain compare"
