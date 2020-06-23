#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from .preshared_key import PresharedKey
from .private_key import PrivateKey
from .public_key import PublicKey

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
            for peer in message.get_attr('WGDEVICE_A_PEERS') or []:
                public_key = peer.get_attr('WGPEER_A_PUBLIC_KEY')
                assert public_key is not None
                if public_key is not None:
                    public_key = PublicKey(public_key)
                if public_key not in self.peers:
                    preshared_key = peer.get_attr('WGPEER_A_PRESHARED_KEY')
                    if not spill_preshared_keys:
                        preshared_key = preshared_key is not None
                    elif preshared_key is not None:
                        preshared_key = PresharedKey(preshared_key)
                    last_handshake_time = peer.get_attr('WGPEER_A_LAST_HANDSHAKE_TIME')
                    if not last_handshake_time > 0:
                        last_handshake_time = None
                    self.peers[public_key] = {
                        'preshared_key': preshared_key,
                        'endpoint': peer.get_attr('WGPEER_A_ENDPOINT'),
                        'persistent_keepalive_interval': peer.get_attr('WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL'),
                        'last_handshake_time': last_handshake_time,
                        'rx_bytes': peer.get_attr('WGPEER_A_RX_BYTES'),
                        'tx_bytes': peer.get_attr('WGPEER_A_TX_BYTES'),
                        'allowedips': [],
                        'protocol_version': peer.get_attr('WGPEER_A_PROTOCOL_VERSION'),
                    }
                for allowedip in peer.get_attr('WGPEER_A_ALLOWEDIPS') or []:
                    self.peers[public_key]['allowedips'].append(allowedip.network())

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
