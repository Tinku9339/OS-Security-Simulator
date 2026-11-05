import hashlib, json, time

class AuditLog:
    """Append-only log; each entry stores SHA-256 of (previous hash + entry) so edits are detectable."""
    def __init__(self, clock=time.time): self.entries, self.clock = [], clock
    def log(self, user, action, target, allowed, reason=""):
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        e = dict(ts=self.clock(), user=user, action=action, target=target, allowed=allowed, reason=reason, prev=prev)
        e["hash"] = self._h(e); self.entries.append(e)
    @staticmethod
    def _h(e):
        body = {k: v for k, v in e.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    def verify(self):
        prev = "0" * 64
        for i, e in enumerate(self.entries):
            if e["prev"] != prev or e["hash"] != self._h(e): return False, i
            prev = e["hash"]
        return True, None
