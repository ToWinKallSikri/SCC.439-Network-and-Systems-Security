"""
SCC.439 - Individual Programming Assessment
This file contains several utility functions used during the communication between the NIDS client and the SIEM server.
These funcitons hel create and check secure PDUs and ensure a secure connection between the endpoints (encryption, CRC, HMAC).
"""

import json
import base64
from datetime import datetime, timezone
from zlib import crc32
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

# Determine import based on execution context
try:
    from components.chap_pdu import Pdu
except ImportError:
    try:
        from chap_pdu import Pdu
    except ImportError:
        # Fallback for some contexts
        from .chap_pdu import Pdu


"""
Creates a fully secured PDU with Timestamp, AES, HMAC, and CRC.
payload: dict (will be json dumped) or literal string (e.g. 'none')
"""
def create_secure_pdu(msgtype, payload, shared_key, encrypt_body=False):
    # 1. Body Processing
    if payload is None:
        body_content = 'none'
    elif isinstance(payload, dict) or isinstance(payload, list):
        json_str = json.dumps(payload)
        if encrypt_body:
            key_hash = SHA256.new(shared_key).digest()
            cipher = AES.new(key_hash, AES.MODE_ECB)
            encrypted = cipher.encrypt(pad(json_str.encode(), AES.block_size))
            body_content = base64.b64encode(encrypted).decode()
        else:
            body_content = json_str
    else:
        # String or other primitives
        body_content = payload

    # 2. Header
    timestamp = datetime.now(timezone.utc).timestamp()
    header = {"msgtype": msgtype, "timestamp": timestamp}

    # 3. Security Section
    security = {}
    if encrypt_body:
        security['encryption'] = "AES256_ECB"
    else:
        security['encryption'] = "none"

    # 4. HMAC
    # Sign Header + Body + Security(w/o HMAC)
    pdu_base = Pdu(header=header, body=body_content, security=security)
    data_to_sign = json.dumps(pdu_base.to_dict(), sort_keys=True).encode()
    h = HMAC.new(shared_key, digestmod=SHA256)
    h.update(data_to_sign)
    security['hmac'] = {'type': 'SHA256', 'hash': h.hexdigest()}

    # 5. CRC
    # Sign PDU with HMAC
    pdu_final = Pdu(header=header, body=body_content, security=security)
    data_for_crc = json.dumps(pdu_final.to_dict(), sort_keys=True).encode()
    crc = crc32(data_for_crc)

    final_header = header.copy()
    final_header['crc'] = crc

    return Pdu(header=final_header, body=body_content, security=security)


"""
Verifies CRC, Timestamp, and HMAC.
Returns: (is_valid: bool, reason: str)
"""
def verify_secure_pdu(pdu: Pdu, shared_key, time_window=5.0):
    # 1. CRC Check
    if not pdu.header or 'crc' not in pdu.header:
        return False, "Missing CRC"

    header_no_crc = pdu.header.copy()
    recieved_crc = header_no_crc['crc']
    del header_no_crc['crc']

    pdu_check = Pdu(header=header_no_crc, body=pdu.body, security=pdu.security)
    calc_crc = crc32(json.dumps(pdu_check.to_dict(), sort_keys=True).encode())

    if calc_crc != recieved_crc:
            return False, "CRC Mismatch"

    # 2. Timestamp freshness check within a 5 seconds time window. (Avoid replay attacks)
    ts = pdu.header.get('timestamp')
    if not ts:
        return False, "Missing Timestamp"
    current_ts = datetime.now(timezone.utc).timestamp()
    if abs(current_ts - ts) > time_window:
        return False, f"Timestamp expired/replay (diff={abs(current_ts - ts):.2f}s)"

    # 3. HMAC check signature
    if not pdu.security or 'hmac' not in pdu.security:
            return False, "Missing Security/HMAC"

    recieved_hmac = pdu.security['hmac']['hash']
    sec_no_hmac = pdu.security.copy()
    del sec_no_hmac['hmac']

    pdu_verify = Pdu(header=header_no_crc, body=pdu.body, security=sec_no_hmac)
    data_verify = json.dumps(pdu_verify.to_dict(), sort_keys=True).encode()

    h = HMAC.new(shared_key, digestmod=SHA256)
    h.update(data_verify)

    try:
        h.hexverify(recieved_hmac)
    except ValueError:
        return False, "HMAC Verify Failed"

    return True, "OK"


"""
Decrypts AES256_ECB body content if present, after the previous checks.
"""
def decrypt_pdu_body(pdu: Pdu, shared_key):
    # Decryption using AES cipher
    try:
        if pdu.security and pdu.security.get('encryption') == 'AES256_ECB':
            encrypted_bytes = base64.b64decode(pdu.body)
            key_hash = SHA256.new(shared_key).digest()
            cipher = AES.new(key_hash, AES.MODE_ECB)
            dec_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
            return json.loads(dec_bytes)
        else:
            # Assume plain text or valid json string
            return json.loads(pdu.body) if isinstance(pdu.body, str) else pdu.body
    except Exception as e:
        print(f"Decryption/Parse error: {e}")
        return None
