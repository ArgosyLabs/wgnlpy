#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from .key import Key

from secrets import token_bytes

class PresharedKey(Key):
    def __init__(self, key=None):
        if isinstance(key, type(None)):
            super().__init__()
        elif isinstance(key, (type(None), PresharedKey, bytes, bytearray, str)):
            super().__init__(key)
        else:
            raise TypeError("key must be PresharedKey, bytes, bytearray, or str")

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
