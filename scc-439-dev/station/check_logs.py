"""
SCC.439 - Individual Programming Assessment
This class allows the user to verify the integrity of the logs. A log is signed with an HMAC that can be verified only with the password
shared between the logger verifier and the siem server.
Therefore, an instance of the logger verifier is run to check if any of the stored logs has been tampered.
"""

from secure_logger.verifylogging import VerifyLogging
import siem_server

def check():
    # Retrieve log file name and password used to log securily (using HMAC)
    logfile = siem_server.LOG_FILE
    password = siem_server.LOG_PASSWORD

    print(f"[*] Verifying log file: {logfile}")
    # Create a verify logging object
    verifier = VerifyLogging()
    try:
        # Container set up to contain eventual errors in the logged lines
        errors = verifier.verify(logfile, password)
    except FileNotFoundError:
        print("[-] Log file not found. Run the server and generate alerts first!")
        return

    print(f"[+] Scanned {verifier.entries_count} entries.")
    # Checks if there are any errors and eventually prints them
    if verifier.error_count == 0:
        print(f"[SUCCESS] All entries verified with HMAC password '{password}'.")
    else:
        print(f"[!] Found {verifier.error_count} integrity errors!")
        print("\tBad lines:", verifier.error_lines)
        print("\n[Details of Tampered Lines]")
        for line_num, content in errors.items():
            print(f"\tLine {line_num}: {content}")

if __name__ == "__main__":
    check()
