#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from .sockaddr_in import sockaddr_in
from .sockaddr_in6 import sockaddr_in6

from ipaddress import ip_address, IPv4Address, IPv6Address

def sockaddr(addr, **kwargs):
    if not isinstance(addr, (IPv4Address, IPv6Address)):
        addr = ip_address(addr)

    if isinstance(addr, IPv4Address):
        return sockaddr_in(addr=addr, **kwargs)
    elif isinstance(addr, IPv6Address):
        return sockaddr_in6(addr=addr, **kwargs)
    else:
        raise NotImplementedError

#
