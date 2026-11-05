# OS Security Simulator (Group 19, CIC-305T)
Educational simulator of three OS security controls: authentication, access control, encryption (+ tamper-evident audit log).

Requirements: Python 3.10+, `pip install cryptography`

    python3 tests.py            # 33 unit tests
    python3 run_experiments.py  # writes results/experiment_results.json

Modules: ossec/auth.py (PBKDF2, lockout, TOTP), ossec/access.py (mode bits, ACL, MAC, path check),
ossec/vault.py (AES-256-GCM + scrypt), ossec/audit.py (hash-chained log), ossec/system.py (integration).
`InsecureUserStore` and the naive path join are deliberately vulnerable baselines used only in experiments.
