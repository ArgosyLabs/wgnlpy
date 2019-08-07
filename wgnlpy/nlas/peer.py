#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from enum import Enum
from pyroute2.netlink import nla

class peer(nla):
    from . import sockaddr, timespec, allowedip

    nla_map = (
        ('WGPEER_A_UNSPEC', 'none'),
        ('WGPEER_A_PUBLIC_KEY', 'cdata'),
        ('WGPEER_A_PRESHARED_KEY', 'cdata'),
        ('WGPEER_A_FLAGS', 'uint32'),
        ('WGPEER_A_ENDPOINT', 'sockaddr'),
        ('WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL', 'uint16'),
        ('WGPEER_A_LAST_HANDSHAKE_TIME', 'timespec'),
        ('WGPEER_A_RX_BYTES', 'uint64'),
        ('WGPEER_A_TX_BYTES', 'uint64'),
        ('WGPEER_A_ALLOWEDIPS', '*allowedip'),
        ('WGPEER_A_PROTOCOL_VERSION', 'uint32'),
    )

    class flag(Enum):
        REMOVE_ME = 1 << 0
        REPLACE_ALLOWEDIPS = 1 << 1

#
