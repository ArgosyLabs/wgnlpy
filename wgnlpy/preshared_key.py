#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from .key import Key

from secrets import token_bytes

class PresharedKey(Key):
    def __init__(self, key=bytes(32)):
        if not isinstance(key, (PresharedKey, bytes, bytearray, str)):
            raise TypeError("key must be PresharedKey, bytes, bytearray, or str")

        super().__init__(key)

    def __eq__(self, other):
        if isinstance(other, Key) and not isinstance(other, PresharedKey):
            return NotImplemented

        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()

    @staticmethod
    def generate():
        return PresharedKey(token_bytes(32))

#
