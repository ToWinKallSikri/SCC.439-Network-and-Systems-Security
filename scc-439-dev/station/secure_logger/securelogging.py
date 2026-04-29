"""
SCC.439 - Individual Programming Assessment
This class allows the SIEM server to generate logs and secure them to avoid tampering once they are stored in the chosen file.
The logger gives as an output a log with the following format: "timestamp::level::message::hmac"
The log is signed with an HMAC that can be verified only with the password shared between the logger verifier and the siem server.
Therefore, once the log is created, using the check_logs.py script, an instance of the logger verifier can be run to check if any of the
stored logs has been tampered.
"""

from datetime import datetime, timezone
from Cryptodome.Hash import HMAC, SHA256

class SecureLogging:
    def __init__(self):
        self.entry_count = 0
        self.file_name = "none"
        self._filehandler = None
        self._password = None  # bytes

    def open(self, file_name, password=None):
        # Part 1: open(file_name)
        # Part 2: open(file_name, password)
        self.close()
        # Recursive call to open and close the file (resoruce release)
        self._filehandler = open(file_name, "a", encoding="utf-8")
        self.file_name = file_name
        self.entry_count = 0
        self._password = password.encode("utf-8") if isinstance(password, str) else password

    def close(self):
        if self._filehandler is not None:
            self._filehandler.close()
        self._filehandler = None
        self.file_name = "none"
        self._password = None

    def _utc_timestamp(self) -> str:
        # Human readable UTC timestamp
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _compute_hmac_hex(self, message: str) -> str:
        if self._password is None:
            raise ValueError("Password is required to compute HMAC")
        h = HMAC.new(self._password, digestmod=SHA256)
        h.update(message.encode("utf-8"))
        return h.hexdigest()

    def log(self, level: int, message: str):
        if self._filehandler is None:
            raise RuntimeError("No log file open")

        ts = self._utc_timestamp()
        base = f"{ts}::{level}::{message}"

        # Part 1 output
        line = base

        # Part 2: append HMAC(timestamp::level::message, password)
        if self._password is not None:
            mac = self._compute_hmac_hex(base)
            line = f"{base}::{mac}"

        self._filehandler.write(line + "\n")
        self._filehandler.flush()
        self.entry_count += 1
