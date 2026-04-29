"""
SCC.439 - Individual Programming Assessment
This script provides a secure communication channel between the SIEM server and the NIDS client with mutual CHAP auth and later each payload
of the sent packets is verified through the utility functions provided in the file secure_ops.oy. Moreover, after the CHAP authentication
it waits for the alerts.
"""

import socket
import base64
import json
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from components.chap_pdu import Pdu, send_pdu, recv_pdu
from components.secure_ops import create_secure_pdu, verify_secure_pdu, decrypt_pdu_body
from secure_logger.securelogging import SecureLogging

# Hardcoded credentials and system settings
SERVER_PORT = 9999
SERVER_USER = "siem_server"
SERVER_PASS = "server_secret_123"
CLIENT_USERS = {"nids_client": "client_agent_secret_123"}
SHARED_KEY = b"SCC.439_Programming_Assessment32" # 32 bytes for AES-256
LOG_FILE = "siem_alerts.log"
LOG_PASSWORD = "log_integrity_secret"

# Initialize Secure Logger
logger = SecureLogging()
# Open the log file to write more on it and save logs - later they can be checked
logger.open(LOG_FILE, LOG_PASSWORD)

"""
Function to hash bytes given in input
"""
def sha256_hex(data: bytes) -> str:
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()

"""
The server socket opens and waits for the NIDS to connnect, authenticate itself and 
later, receives ACKs, NACKs and alerts
"""
def run_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", SERVER_PORT))
    s.listen(5)
    print(f"[SIEM] listening on 0.0.0.0:{SERVER_PORT} as user '{SERVER_USER}'")

    while True:
        client, address = s.accept()

        print(f"[+] Connection from {address}")
        # Call to the function to handle the client in the different phases
        handle_client(client)

"""
Function to handle mutual CHAP and PDU check to avoid tampering
"""
def handle_client(client):
    # -- Phase 1: CHAP --
    try:
        # 1. Mutual CHAP authentication - Wait for hello from client and then authentication
        hello = recv_pdu(client, timeout=10)
        if hello.header.get("msgtype") != "hello":
            print("[-] Expected hello; closing connection")
            client.close()
            return
        # Retrieve client username and verify it against the provided one (hardcoded)
        c_username = None
        if isinstance(hello.body, dict):
            c_username = hello.body.get("username")

        if c_username not in CLIENT_USERS:
            print("[-] Unknown client user; closing immediately")
            client.close()
            return

        print(f"[+] Client '{c_username}' initiating authentication")

        # 2. Sending challenge to the client - Client authentication
        c1 = get_random_bytes(32)
        send_pdu(client, Pdu(
                header={"msgtype": "challenge"},
                body={"challenge_b64": base64.b64encode(c1).decode("utf-8")}
        ))

        # 3. Wait and recevieve response from client (MAX 10s wait)
        r = recv_pdu(client, timeout=10)
        if r.header.get("msgtype") != "response":
            print("[-] Expected response; closing")
            client.close()
            return
        # Recevied challenge response
        got = r.body.get("response_hex")
        # Expected CHAP value
        exp = sha256_hex(c1 + CLIENT_USERS[c_username].encode("utf-8"))
        # If values don't match auth failed - send secure NACK
        if got != exp:
            send_nack(client)
            print("[-] Client Auhtentication failed; NACK sent")
            client.close()
            return

        print(f"[+] Client '{c_username}' authenticated successfully")
        # 4. If values match - auth OK - send secure ACK
        send_ack(client)

        # Phase 2:  Wait for client CHAP - (MAX 10s wait) - Server Authentication
        c2_pdu = recv_pdu(client, timeout=10)
        is_valid, reason = verify_secure_pdu(c2_pdu, SHARED_KEY)

        if not is_valid:
            print(f"[-] Challenge2 verification failed: {reason}")
            client.close()
            return

        if c2_pdu.header.get("msgtype") != "challenge2":
            print(f"[-] Expected msgtype: challenge2; got {c2_pdu.header.get('msgtype')} instead; closing")
            client.close()
            return

        # 1. Decrypt/Parse the body to get the dictionary
        c2_body = decrypt_pdu_body(c2_pdu, SHARED_KEY)
        if not isinstance(c2_body, dict) or "challenge_b64" not in c2_body:
            print("[-] Invalid challenge2 body format or missing challenge_b64")
            client.close()
            return

        c2 = base64.b64decode(c2_body["challenge_b64"])

        resp2_hex = sha256_hex(c2 + SERVER_PASS.encode("utf-8"))
        # 2. Send response to client challenge - secure PDU
        response2_pdu = create_secure_pdu(
            "response2",
            {"server_username": SERVER_USER, "response_hex": resp2_hex},
            SHARED_KEY,
            encrypt_body=False
        )
        send_pdu(client, response2_pdu)
        print("[+] Server auth response sent")

        # 3. Wait  for final ack/nack from client (MAX 10s wait)
        final = recv_pdu(client, timeout=10)
        is_valid, reason = verify_secure_pdu(final, SHARED_KEY)

        if not is_valid:
            print(f"[-] Final ACK verification failed: {reason}")
            client.close()
            return
        # 4. Check wether or not verification was successful
        final_msgtype = final.header.get("msgtype")

        if final_msgtype != "ack":
            print("[-] Rejected, final response from client:", final_msgtype)
            return

        print("[+] Mutual CHAP completed, switching to Alert Mode")

        # -- Phase 3: Listening for PDUs containing alerts. (Sent through secure connection)
        while True:
            # Keep listening, wait for alerts, no timeout
            a_pdu = recv_pdu(client, timeout=None)
            # When alerts received they are parsed and displayed on the CLI
            parse_secure_alerts(a_pdu, client)

    except socket.timeout:
            print("[-] Server timeout; closing")
    except Exception as e:
        print(f"[-] Connection Error: {e}")
    finally:
        client.close()
        print("[-] Connection closed")


"""
Fucntion to process the received PDUs containing alerts from the client agent
"""
def parse_secure_alerts(received_pdu, client_socket):

    nack_counter = 0

    # Use utility from secure_ops.pyto verify PDU (CRC, Timestamp, HMAC)
    is_valid, reason = verify_secure_pdu(received_pdu, SHARED_KEY, time_window=5.0)

    # If not valid send NACK
    if not is_valid:
        print(f"[-] Secure Alert Verification Failed: {reason}")
        if nack_counter < 3:
            send_nack(client_socket)
            nack_counter += 1
        return

    print("[+] Secure pdu verified (CRC, TS, HMAC)")
    # If PDU is verified decrypt the body with the shared key
    alert_payload = decrypt_pdu_body(received_pdu, SHARED_KEY)

    # Ensure payload is a dictionary
    alert_dict = None

    # Payload type checking
    if isinstance(alert_payload, dict):
        alert_dict = alert_payload
    elif isinstance(alert_payload, str):
        try:
            # Try to parse it if it came out as a JSON string
            alert_dict = json.loads(alert_payload)
        except json.JSONDecodeError:
            print(f"[-] Failed to decode JSON from string body: {alert_payload[:50]}...")

    # Now check if it is a valid dictionary and print the received alerts on the CLI
    if isinstance(alert_dict, dict):
        send_ack(client_socket)

        # Log the alert securely
        try:
            log_msg = json.dumps(alert_dict)
            # The SIEM server communicates to the logger to write logs in the chosen file
            logger.log(1, log_msg)
            print(f"[LOG] Alert secured in {LOG_FILE}")
        except Exception as log_err:
            print(f"[-] Logging failed: {log_err}")

        print(f"\n{'='*60}")
        print(f"[*** ALERT RECEIVED ***]")
        print(f"  Type: {alert_dict.get('type', 'Unknown')}")
        print(f"  Source/Target: {alert_dict.get('source/target', 'Unknown')}")
        print(f"  Info: {alert_dict.get('info', 'Unknown')}")
        print(f"  Timestamp: {alert_dict.get('timestamp', 'Unknown')}")
        print(f"{'='*60}\n")
    else:
        print(f"[-] Invalid alert format. Expected dict, got {type(alert_payload)}")
        send_nack(client_socket)

"""
Utility function to send ACKs through secured process
"""
def send_ack(client_socket):
    """Send ACK message with timestamp, HMAC, and CRC"""
    pdu = create_secure_pdu("ack", "none", SHARED_KEY)
    send_pdu(client_socket, pdu)

"""
Utility function to send NACKs through secured process
"""
def send_nack(client_socket):
    """Send NACK message with timestamp, HMAC, and CRC"""
    pdu = create_secure_pdu("nack", "none", SHARED_KEY)
    send_pdu(client_socket, pdu)


if __name__ == "__main__":
    run_server()