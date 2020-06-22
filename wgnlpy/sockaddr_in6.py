#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import ctypes
from socket import AF_INET6
from ipaddress import IPv6Address

class sockaddr_in6(ctypes.Structure):
    _fields_ = (
        ('_family', ctypes.c_uint16),
        ('port', ctypes.c_uint16.__ctype_be__),
        ('flowinfo', ctypes.c_uint32.__ctype_be__),
        ('_addr', ctypes.c_ubyte * 16),
        ('scope_id', ctypes.c_uint32),
    )

    def __init__(self, **kwargs):
        super().__init__(_family=self.family)
        for key, value in kwargs.items():
            if not hasattr(self, key):
                raise AttributeError
            setattr(self, key, value)

    def __str__(self):
        if self.scope_id > 0:
            return f'[{self.addr}%{self.scope_id}]:{self.port}'
        else:
            return f'[{self.addr}]:{self.port}'

    def __repr__(self):
        return repr({
            'family': self.family,
            'port': self.port,
            'flowinfo': self.flowinfo,
            'addr': self.addr,
            'scope_id': self.scope_id,
        })

    @property
    def family(self):
        return AF_INET6

    @property
    def addr(self):
        return IPv6Address(bytes(self._addr))

    @addr.setter
    def addr(self, value):
        if not isinstance(value, IPv6Address):
            value = IPv6Address(value)

        self._addr = type(self._addr).from_buffer_copy(value.packed)

#
