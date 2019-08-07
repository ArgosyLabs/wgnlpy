#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from enum import Enum
from pyroute2.netlink import genlmsg

class device(genlmsg):
    VERSION = 1

    class type(Enum):
        GET_DEVICE = 0
        SET_DEVICE = 1

    @staticmethod
    def get_device():
        self = device()
        self['cmd'] = self.type.GET_DEVICE.value
        self['version'] = self.VERSION
        return self

    @staticmethod
    def set_device():
        self = device()
        self['cmd'] = self.type.SET_DEVICE.value
        self['version'] = self.VERSION
        return self

    from . import peer

    nla_map = (
        ('WGDEVICE_A_UNSPEC', 'none'),
        ('WGDEVICE_A_IFINDEX', 'uint32'),
        ('WGDEVICE_A_IFNAME', 'asciiz'),
        ('WGDEVICE_A_PRIVATE_KEY', 'cdata'),
        ('WGDEVICE_A_PUBLIC_KEY', 'cdata'),
        ('WGDEVICE_A_FLAGS', 'uint32'),
        ('WGDEVICE_A_LISTEN_PORT', 'uint16'),
        ('WGDEVICE_A_FWMARK', 'uint32'),
        ('WGDEVICE_A_PEERS', '*peer'),
    )

    class flag(Enum):
        REPLACE_PEERS = 1 << 0

#
