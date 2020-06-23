#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from .private_key import PrivateKey
from .public_key import PublicKey
from .wireguardpeer import WireGuardPeer

class WireGuardInfo(object):
    __slots__ = (
        "ifindex",
        "ifname",
        "private_key",
        "public_key",
        "listen_port",
        "fwmark",
        "peers",
    )

    def __init__(self, messages, spill_private_key, spill_preshared_keys):
        self.ifindex = messages[0].get_attr('WGDEVICE_A_IFINDEX')
        self.ifname = messages[0].get_attr('WGDEVICE_A_IFNAME')
        self.private_key = messages[0].get_attr('WGDEVICE_A_PRIVATE_KEY')
        if not spill_private_key:
            self.private_key = self.private_key is not None
        elif self.private_key is not None:
            self.private_key = PrivateKey(self.private_key)
        self.public_key = messages[0].get_attr('WGDEVICE_A_PUBLIC_KEY')
        if self.public_key is not None:
            self.public_key = PublicKey(self.public_key)
        self.listen_port = messages[0].get_attr('WGDEVICE_A_LISTEN_PORT')
        self.fwmark = messages[0].get_attr('WGDEVICE_A_FWMARK')

        self.peers = { }

        for message in messages:
            wgp = lambda p: WireGuardPeer(p, spill_preshared_keys)
            for peer in map(wgp, message.get_attr('WGDEVICE_A_PEERS') or []):
                assert peer.public_key not in self.peers
                self.peers[peer.public_key] = peer

    def __repr__(self):
        return repr({
            'ifindex': self.ifindex,
            'ifname': self.ifname,
            'private_key': self.private_key,
            'public_key': self.public_key,
            'listen_port': self.listen_port,
            'fwmark': self.fwmark,
            'peers': self.peers,
        })

#
