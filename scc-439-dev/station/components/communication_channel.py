"""
SCC.439 - Individual Programming Assessment
This class provides a secure communication channel between the NIDS client and the SIEM server with mutual CHAP auth and later each payload
of the sent packets is verified through the utility functions provided in the file secure_ops.oy
The NIDS uses this class to send alerts securely to the SIEM.
"""

import time
from components.chap_pdu import Pdu, send_pdu, recv_pdu
from components.secure_ops import create_secure_pdu, verify_secure_pdu, decrypt_pdu_body
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import base64
import socket

# Hardcoded credentials and system settings
SERVER_IP = "172.20.0.2" # Station IP address (where the NIDS and the SIEM sever are running and communicate on port 9999)
SERVER_PORT = 9999
CLIENT_USER = "nids_client"
CLIENT_PASS = "client_agent_secret_123"
SERVER_EXPECTED_USER = "siem_server"
SERVER_EXPECTED_PASS = "server_secret_123"
SHARED_KEY = b"SCC.439_Programming_Assessment32"


class SecureChannel:
    # Setup of the class to instantiate a global socket and
    # a flag that shows if the connection is alive
    def __init__(self):
        self.sock = None
        self.connected = False
    """
    Function to connect the NIDS to the SIEM server. First authenticating with CHAP
    then each packet, even ACK or NACKs are thourghly check via the CRC, timestamp and the HMAC
    """
    def connect(self):
        while not self.connected:

            try:
                # Socket setup for IPV4 and TCP
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Starting the connection to the server socket
                self.sock.connect((SERVER_IP, SERVER_PORT))
                # Call to the authentication method that will return the outcome of the mutual CHAP
                if self.authenticate():
                    # If the CHAP has a positive outcome the connection is flagged as alive
                    self.connected = True
                    print("[+] Connected & Authenticated to SIEM")
                else:
                    print("[-] Auth failed, retrying...")
                    self.sock.close()
                    time.sleep(5)

            except Exception as e:
                print(f"[-] Connection failed ({e}), retrying in 5s...")
                time.sleep(5)


    def authenticate(self):
        # --- MUTUAL CHAP CLIENT SIDE ---
        try:
            # Phase 1: Send hello to start CHAP
            send_pdu(self.sock, Pdu(
                header={"msgtype": "hello"},
                body={"username": CLIENT_USER}
                ))
            # 1. Wait for ther challenge from the server
            chal = recv_pdu(self.sock, timeout=10)
            # 2. Check if it is the correct header
            if chal.header.get("msgtype") != "challenge":
                print("[-] Expected challenge not receuved; closing")
                return False
            # 3. Prepare answer and send back to server
            c1 = base64.b64decode(chal.body["challenge_b64"])
            r1 = SHA256.new(c1 + CLIENT_PASS.encode("utf-8")).hexdigest()
            send_pdu(self.sock, Pdu(
                header={"msgtype": "response"}, 
                body={"response_hex": r1}
                ))
            # Wait for challenge submission result
            result = recv_pdu(self.sock, timeout=10)
            # 4. Verify packet
            is_valid, reason = verify_secure_pdu(result, SHARED_KEY)

            # --- VERIFY SECURE ACK ---
            if not is_valid:
                print(f"[-] Auth ACK verification failed: {reason}")
                return False

            if result.header.get("msgtype") == "nack":
                print("[-] Server rejected client auth (secure NACK)")
                return False

            elif result.header.get("msgtype") != "ack":
                print(f"[-] Expected ack, got {result.header.get('msgtype')}")
                return False

            print("[+] Client auth OK (Secure ACK verified)")

            # Phase 2: client challenges server
            c2 = get_random_bytes(32)
            # 1. Send challenge to the sever with shared key
            challenge2_pdu = create_secure_pdu(
                "challenge2",
                {"challenge_b64": base64.b64encode(c2).decode("utf-8")},
                SHARED_KEY,
                encrypt_body=False
            )
            send_pdu(self.sock, challenge2_pdu)

            # 2. Wait for answer to the challenge and verify authenticity
            resp2 = recv_pdu(self.sock, timeout=10)
            is_valid, reason = verify_secure_pdu(resp2, SHARED_KEY)

            if not is_valid:
                print(f"[-] Server response2 verification failed: {reason}")
                self.send_nack()
                return False
            # 3. Check header
            if resp2.header.get("msgtype") != "response2":
                print(f"[-] Expected response2, got {resp2.header.get('msgtype')}")
                self.send_nack()
                return False

            # 4. Verify server identity
            resp2_body = decrypt_pdu_body(resp2, SHARED_KEY)
            if not isinstance(resp2_body, dict):
                print("[-] Invalid response2 body format")
                self.send_nack()
                return False
            # 5. Check seerver username against hardcoded values
            server_username_got = resp2_body.get("server_username")
            server_response_hex = resp2_body.get("response_hex")

            if server_username_got != SERVER_EXPECTED_USER:
                print(f"[-] Server username mismatch!,  Got '{server_username_got}'")
                self.send_nack()
                return False
            # 6. Check server expected response
            expected = SHA256.new(c2 + SERVER_EXPECTED_PASS.encode("utf-8")).hexdigest()
            if server_response_hex != expected:
                print("[-] Server auth FAIL (hash mismatch)")
                self.send_nack()
                return False

            print("[+] Server auth OK (Secure Response2 verified)")

            # 7. Send Final ACK (secure PDU)
            self.send_ack()
            return True

        except Exception as e:
            print(f"Auth error: {e}")
            return False


    """
    Utility function to send ACKs through secured process
    """
    def send_ack(self):
        """Send ACK message with timestamp, HMAC, and CRC"""
        if not self.sock: return
        pdu = create_secure_pdu("ack", "none", SHARED_KEY)
        send_pdu(self.sock, pdu)

    """
    Utility function to send NACKs through secured process
    """
    def send_nack(self):
        """Send NACK message with timestamp, HMAC, and CRC"""
        if not self.sock: return
        pdu = create_secure_pdu("nack", "none", SHARED_KEY)
        send_pdu(self.sock, pdu)


    """
    Function to send alerts to the SIEM server,once connected. Each packet is sent with a secure PDU (Encryption, HMAC, CRC)
    """
    def send_alert(self, alert_dict):
        if not self.connected:
            self.connect()

        try:
            # Use utility from secure_ops.py to creation Encryption, HMAC, CRC PDU
            final_pdu = create_secure_pdu("alert", alert_dict, SHARED_KEY, encrypt_body=True)

            max_retries = 3
            nack_counter = 0

            print(f"[>] Sending alert: {alert_dict['type']}")
            # Attempt to send alert with nack counter and max retries
            for attempt in range(1, max_retries + 1):
                print(f"\tAttempt {attempt}/{max_retries}...", end=" ", flush=True)

                try:
                    # Sending secure PDU
                    send_pdu(self.sock, final_pdu)

                    # Wait for ACK
                    resp_pdu = recv_pdu(self.sock, timeout=10)

                    # Use utility to verify ACK
                    is_valid, reason = verify_secure_pdu(resp_pdu, SHARED_KEY)

                    if not is_valid:
                        print(f"[-] Invalid ACK: {reason}")
                        continue

                    msg_type = resp_pdu.header.get('msgtype')
                    # ACK check, NACK with nack counter and finally max retries check
                    if msg_type == 'ack':
                        print("[+] Secure ACK Verified!")
                        break
                    elif msg_type == 'nack':
                        print("[+] Secure NACK Verified!")
                        nack_counter += 1
                        if nack_counter >= 3:
                            print("[-] Max NACKs. Aborting.")
                            break
                    elif attempt < max_retries:
                        print("[*] Reconnecting...")
                        self.connect() # Try to reconnect once
                    else:
                        print("[-] Failed to send alert after retries")

                except socket.timeout:
                    print("TIMEOUT waiting for ACK")
                except Exception as inner_e:
                    print(f"Error: {inner_e}")

        except Exception as e:
            print(f"[-] Send error: {e}")
            self.connected = False


