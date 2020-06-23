#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from base64 import b64encode, b64decode

class Key:
    __slots__ = ('_value')

    def __init__(self, key=bytes(32)):
        if isinstance(key, Key):
            self._value = key._value
        elif isinstance(key, bytes):
            self._value = key
        elif isinstance(key, bytearray):
            self._value = bytes(key)
        elif isinstance(key, str):
            self._value = b64decode(key)
        else:
            raise TypeError()

        assert isinstance(self._value, bytes)
        assert 32 == len(self._value)

    def __str__(self):
        return b64encode(self._value).decode('utf-8')

    def __bytes__(self):
        return self._value

    def __repr__(self):
        return f'{type(self).__name__}({repr(str(self))})'

    def __bool__(self):
        return self._value != bytes(32)

    def __eq__(self, other):
        if isinstance(other, Key):
            return self._value == other._value
        elif isinstance(other, (bytes, bytearray)):
            return self._value == other
        elif isinstance(other, str):
            return self._value == b64decode(other)
        else:
            return NotImplemented

    def __hash__(self):
        return hash(self._value)

#
