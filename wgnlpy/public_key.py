#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from .key import Key

from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

class PublicKey(Key):
    def __init__(self, key=None):
        if key is None:
            super().__init__()
        elif isinstance(key, PublicKey):
            super().__init__(key)
        elif isinstance(key, X25519PublicKey):
            super().__init__(key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ))
        elif isinstance(key, (bytes, bytearray)):
            super().__init__(X25519PublicKey.from_public_bytes(key).public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ))
        elif isinstance(key, str):
            super().__init__(X25519PublicKey.from_public_bytes(b64decode(key)).public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ))
        else:
            raise TypeError("key must be PublicKey, bytes, bytearray, or str")

    def __eq__(self, other):
        if isinstance(other, Key) and not isinstance(other, PublicKey):
            return NotImplemented

        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()

#
