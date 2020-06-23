#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from .key import Key
from .public_key import PublicKey

from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

class PrivateKey(Key):
    def __init__(self, key=None):
        if key is None:
            super().__init__()
        elif isinstance(key, PrivateKey):
            super().__init__(key)
        elif isinstance(key, X25519PrivateKey):
            super().__init__(key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        elif isinstance(key, (bytes, bytearray)):
            super().__init__(X25519PrivateKey.from_private_bytes(key).private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        elif isinstance(key, str):
            super().__init__(X25519PrivateKey.from_private_bytes(b64decode(key)).private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        else:
            raise TypeError("key must be PrivateKey, bytes, bytearray, or str")

    def __eq__(self, other):
        if isinstance(other, Key) and not isinstance(other, PrivateKey):
            return NotImplemented

        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()

    def public_key(self):
        return PublicKey(X25519PrivateKey.from_private_bytes(bytes(self)).public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ))

        if isinstance(other, Key) and not isinstance(other, PrivateKey):
            return NotImplemented

        return super().__eq__(other)

    @staticmethod
    def generate():
        return PrivateKey(X25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ))

#
