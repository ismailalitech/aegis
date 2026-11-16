"""Aegis wire format v1: canonical JSON bodies, signed with ML-DSA-65.

A message on TCP is a 4-byte big-endian length followed by UTF-8 JSON.
Signed objects look like {"body": {...}, "sig": "<hex>"}; the signature covers
canonical(body) = json.dumps(body, sort_keys=True, separators=(",", ":")).
Labels separate the uses of the one key, so an identity record can never be
replayed as a quote or the other way round.
"""
import hashlib
import json
import struct

LABEL_IDENTITY = b"aegis-identity-v1"
LABEL_QUOTE = b"aegis-quote-v1"
MAX_MSG = 1 << 20


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def send(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv(sock):
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > MAX_MSG:
        raise ValueError("message too large")
    return json.loads(_recv_exact(sock, n).decode())
