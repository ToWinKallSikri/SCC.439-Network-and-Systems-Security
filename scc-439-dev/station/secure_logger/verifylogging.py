"""
SCC.439 - Individual Programming Assessment
This class is used to verify the logs stored in a certain file, based on the congruence of the current HMAC
against the base values of the log (timestamp::level::message) that have been signed using the hardcoded password.
If even one character or number is moved or altered, the HMAC doesn't match, therefore the log has been most likely tampered.
"""

from Cryptodome.Hash import HMAC, SHA256

class VerifyLogging:
    def __init__(self):
        self.file_name = "none"
        self.entries_count = 0
        self.error_count = 0
        self.error_lines = []
        self.errors = {}
    # Verify each line of the log file
    def _verify_line(self, base: str, mac_hex: str, password_bytes: bytes) -> bool:
        h = HMAC.new(password_bytes, digestmod=SHA256)
        h.update(base.encode("utf-8"))
        try:
            h.hexverify(mac_hex)
            return True
        except ValueError:
            return False

    """
    Function called to verify the log file splitting it into each line and each component
    Later each base of the log is checked against the HMAC obtained with password hardcoded and injected from check_logs.py
    The latter retrieves it from the SIEM server.
    """
    def verify(self, file_name: str, password: str):
        self.file_name = file_name
        self.entries_count = 0
        self.error_count = 0
        self.error_lines = []
        self.errors = {}

        pwd = password.encode("utf-8")
        # Read each line of the log file
        with open(file_name, "r", encoding="utf-8") as fh:
            for idx, raw in enumerate(fh, start=1):
                line = raw.rstrip("\n")
                if not line:
                    continue

                self.entries_count += 1

                parts = line.split("::")
                # Expected: timestamp::level::message::hmac
                if len(parts) < 4:
                    self.error_count += 1
                    self.error_lines.append(idx)
                    self.errors[idx] = line
                    continue

                mac_hex = parts[-1]
                # timestamp::level::message
                base = "::".join(parts[:-1])

                ok = self._verify_line(base, mac_hex, pwd)
                if not ok:
                    self.error_count += 1
                    self.error_lines.append(idx)
                    self.errors[idx] = line

        # Failures stored in a dictionary keyed by line number
        return self.errors
