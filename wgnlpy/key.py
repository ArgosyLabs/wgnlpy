#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from base64 import b64encode, b64decode

class Key:
    __slots__ = ('__value')

    def __init__(self, key=bytes(32)):
        if isinstance(key, Key):
            self.__value = key.__value
        elif isinstance(key, bytes):
            self.__value = key
        elif isinstance(key, bytearray):
            self.__value = bytes(key)
        elif isinstance(key, str):
            self.__value = b64decode(key)
        else:
            raise TypeError()

        assert isinstance(self.__value, bytes)
        assert 32 == len(self.__value)

    def __str__(self):
        return b64encode(self.__value).decode('utf-8')

    def __bytes__(self):
        return self.__value

    def __repr__(self):
        return f'{type(self).__name__}({repr(str(self))})'

    def __bool__(self):
        return self.__value != bytes(32)

    def __eq__(self, other):
        if isinstance(other, Key):
            return self.__value == other.__value
        elif isinstance(other, (bytes, bytearray)):
            return self.__value == other
        elif isinstance(other, str):
            return self.__value == b64decode(other)
        else:
            return NotImplemented

    def __hash__(self):
        return hash(self.__value)

#
