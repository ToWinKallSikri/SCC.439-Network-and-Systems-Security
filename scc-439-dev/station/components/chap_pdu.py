"""
SCC.439 - Individual Programming Assessment
This class provides the structure for the Protocol Data Unit that is exchanged through a TCP stream between the NIDS client and the SIEM server.
It also provides auxiliary utility funtions that help converting the given data into a dictionary and viceversa.
"""

import json

class Pdu:
    def __init__(self, header, body, security=None):
        # Class constructor for custom PDU
        self.header = header
        self.body = body
        self.security = security

    """
    Function to convert to dictionary the data given when an instance of the class is created
    """
    def to_dict(self):
        d = {
            "header": self.header,
            "body": self.body
        }
        if self.security is not None:
            d["security"] = self.security
        return d

    """
    Convert a dictionary into a Pdu object
    """
    @classmethod
    def from_dict(cls, data):
        if "header" not in data or "body" not in data:
            raise ValueError("Invalid PDU dictionary: missing header or body")
        return cls(
            header=data["header"],
            body=data["body"],
            security=data.get("security")
        )

    """
    toString function
    """
    def __str__(self):
        return f"PDU(header={self.header}, body={self.body}, security={self.security})"

"""
Aux utility function to consolidate duplicate lines and avoid boilerplate code, in this case to send a PDU
"""
def send_pdu(sock, pdu: Pdu):
    payload = json.dumps(pdu.to_dict(), sort_keys=True) + "\n"
    sock.sendall(payload.encode("utf-8"))

"""
Aux utility function to consolidate duplicate lines and avoid boilerplate code
The funciton send and recieve are made in a way that whenever the "\n" carachter is met
that means that the payload ends. That helps avoiding accidental overlapping in a TCP stream.
NDJSON (newline delimited json), to define boundaries between packets.
"""
def recv_pdu(sock, timeout=None) -> Pdu:
    # Timeout set to None to keep the connection with the socket alive
    if timeout is not None:
        sock.settimeout(timeout)
    else:
        # Explicitly remove timeout if None is passed
        sock.settimeout(None)
    # Initialize a byte buffer
    buf = b""
    # Read the payload until \n is met
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Socket closed while waiting for PDU")
        buf += chunk
    # Consider data only until \n
    line, _rest = buf.split(b"\n", 1)
    data = json.loads(line.decode("utf-8"))
    return Pdu.from_dict(data)
