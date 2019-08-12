#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from struct import unpack_from
from socket import AF_INET, AF_INET6, getaddrinfo
from urllib.parse import urlparse
from pyroute2.netlink import nla_base
from ..sockaddr_in import sockaddr_in
from ..sockaddr_in6 import sockaddr_in6

class sockaddr(nla_base):
    fields = (
        ('value', 's'),
    )

    def encode(self):
        assert isinstance(self.value, (sockaddr_in, sockaddr_in6, ))
        self['value'] = bytes(self.value)
        nla_base.encode(self)

    def decode(self):
        nla_base.decode(self)
        family, = unpack_from("H", self["value"])

        try:
            type = {
                AF_INET: sockaddr_in,
                AF_INET6: sockaddr_in6,
            }[family]
        except:
            raise NotImplementedError

        if isinstance(self['value'], bytearray):
            self.value = type.from_buffer(self['value'])
        elif isinstance(self['value'], bytes):
            self.value = type.from_buffer_copy(self['value'])

    @staticmethod
    def frob(nitz):
        if isinstance(nitz, (sockaddr_in, sockaddr_in6)):
            return nitz

        DEFAULT_PORT = 51820
        url = urlparse("//" + nitz)
        family, *meh, sockaddr = getaddrinfo(url.hostname, url.port or DEFAULT_PORT)[0]

        try:
            type, *fields = {
                AF_INET: (sockaddr_in, 'addr', 'port'),
                AF_INET6: (sockaddr_in6, 'addr', 'port', 'flowinfo', 'scope_id'),
            }[family]
        except:
            raise NotImplementedError

        return type(**dict(zip(fields, sockaddr)))

#
