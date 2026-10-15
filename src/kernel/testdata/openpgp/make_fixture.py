"""Write an OpenPGP test keyring: a primary key (certify+sign), an
encryption-only subkey, and a signing subkey with its back-signature, plus
detached signatures of one document by each of the three keys.

usage: make_fixture.py OUTDIR
"""
import base64
import hashlib
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

TS = 1700000000
UID = b"Greyward OpenPGP fixture <fixture@example.invalid>"
DOC = b"a document only the signing keys may sign\n"


def mpi(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return struct.pack(">H", value.bit_length()) + raw


def key_body(priv):
    numbers = priv.public_key().public_numbers()
    return bytes([4]) + struct.pack(">I", TS) + bytes([1]) + mpi(numbers.n) + mpi(numbers.e)


def frame(body):
    return b"\x99" + struct.pack(">H", len(body)) + body


def fingerprint(body):
    return hashlib.sha1(frame(body)).digest()


def subpacket(kind, data):
    n = len(data) + 1
    if n < 192:
        return bytes([n, kind]) + data
    n -= 192
    return bytes([(n >> 8) + 192, n & 0xFF, kind]) + data


def signature(priv, signer_body, cls, hashed_subs, prefix, unhashed_extra=b""):
    fpr = fingerprint(signer_body)
    subs = (
        subpacket(2, struct.pack(">I", TS))
        + subpacket(33, b"\x04" + fpr)
        + hashed_subs
    )
    hashed = bytes([4, cls, 1, 8]) + struct.pack(">H", len(subs)) + subs
    trailer = b"\x04\xff" + struct.pack(">I", len(hashed))
    data = prefix + hashed + trailer
    value = priv.sign(data, padding.PKCS1v15(), hashes.SHA256())
    unhashed = subpacket(16, fpr[12:]) + unhashed_extra
    return (
        hashed
        + struct.pack(">H", len(unhashed))
        + unhashed
        + hashlib.sha256(data).digest()[:2]
        + mpi(int.from_bytes(value, "big"))
    )


def packet(tag, body):
    n = len(body)
    if n < 192:
        length = bytes([n])
    elif n < 8384:
        n -= 192
        length = bytes([(n >> 8) + 192, n & 0xFF])
    else:
        length = b"\xff" + struct.pack(">I", n)
    return bytes([0xC0 | tag]) + length + body


def crc24(data):
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armor(kind, data):
    text = base64.b64encode(data).decode()
    lines = [text[i:i + 64] for i in range(0, len(text), 64)]
    crc = base64.b64encode(crc24(data).to_bytes(3, "big")).decode()
    return f"-----BEGIN {kind}-----\n\n" + "\n".join(lines) + f"\n={crc}\n-----END {kind}-----\n"


def main():
    out = sys.argv[1]
    primary, enc, sign = (rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3))
    p, e, s = key_body(primary), key_body(enc), key_body(sign)
    flags = lambda f: subpacket(27, bytes([f]))
    self_sig = signature(primary, p, 0x13, flags(0x03), frame(p) + b"\xb4" + struct.pack(">I", len(UID)) + UID)
    enc_binding = signature(primary, p, 0x18, flags(0x0C), frame(p) + frame(e))
    back = signature(sign, s, 0x19, b"", frame(p) + frame(s))
    sign_binding = signature(primary, p, 0x18, flags(0x02), frame(p) + frame(s), subpacket(32, back))
    keyring = (
        packet(6, p) + packet(13, UID) + packet(2, self_sig)
        + packet(14, e) + packet(2, enc_binding)
        + packet(14, s) + packet(2, sign_binding)
    )
    files = {
        "keyring.asc": armor("PGP PUBLIC KEY BLOCK", keyring),
        "document.txt": DOC.decode(),
    }
    for name, priv, body in [("primary", primary, p), ("encrypt-only", enc, e), ("signing-subkey", sign, s)]:
        files[f"by-{name}.asc"] = armor("PGP SIGNATURE", packet(2, signature(priv, body, 0x00, b"", DOC)))
    for name, text in files.items():
        with open(os.path.join(out, name), "w") as f:
            f.write(text)
    print("primary", fingerprint(p).hex().upper())
    print("encrypt-only", fingerprint(e).hex().upper())
    print("signing-subkey", fingerprint(s).hex().upper())


main()
