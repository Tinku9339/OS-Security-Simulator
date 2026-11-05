import posixpath

READ, WRITE, EXEC = "r", "w", "x"

class AccessError(PermissionError): pass

def safe_path(root, path):
    """Normalise a virtual path; reject anything that escapes the root (path traversal)."""
    if "\x00" in path: raise AccessError("null byte in path")
    p = posixpath.normpath(posixpath.join(root, path.lstrip("/")))
    if p != root and not p.startswith(root.rstrip("/") + "/"):
        raise AccessError("path escapes root")
    return p

class FileObj:
    def __init__(self, owner, group, mode=0o640, level=1):
        self.owner, self.group, self.mode, self.level = owner, group, mode, level
        self.acl = {}  # user -> set of permissions (explicit grants/denies via "-")

def _bit(action): return {READ: 4, WRITE: 2, EXEC: 1}[action]

def check(user, uname, obj, action):
    """Decision order: deny-ACL -> admin -> MAC no-read-up -> allow-ACL -> owner/group/other bits."""
    if "-" + action in obj.acl.get(uname, set()): return False, "explicit ACL deny"
    if user["role"] == "admin": return True, "admin role"
    if action == READ and user["clearance"] < obj.level: return False, "MAC: clearance too low"
    if action == WRITE and user["clearance"] > obj.level and obj.level > 0 and user["role"] != "admin":
        return False, "MAC: no write down"
    if action in obj.acl.get(uname, set()): return True, "ACL grant"
    if uname == obj.owner: cls = (obj.mode >> 6) & 7
    elif obj.group in user["groups"]: cls = (obj.mode >> 3) & 7
    else: cls = obj.mode & 7
    return (bool(cls & _bit(action)), "mode bits")
