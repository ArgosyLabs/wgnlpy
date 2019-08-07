#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import ctypes
from socket import AF_INET
from ipaddress import IPv4Address

class sockaddr_in(ctypes.Structure):
    _fields_ = (
        ('_family', ctypes.c_uint16),
        ('port', ctypes.c_uint16.__ctype_be__),
        ('_addr', ctypes.c_ubyte * 4),
        ('_zero', ctypes.c_byte * 8),
    )

    def __init__(self, **kwargs):
        super().__init__(_family=self.family)
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __repr__(self):
        return repr({
            'family': self.family,
            'port': self.port,
            'addr': self.addr,
        })

    @property
    def family(self):
        return AF_INET

    @property
    def addr(self):
        return IPv4Address(bytes(self._addr))

    @addr.setter
    def addr(self, value):
        if not isinstance(value, IPv4Address):
            value = IPv4Address(value)

        self._addr = type(self._addr).from_buffer_copy(value.packed)

#
