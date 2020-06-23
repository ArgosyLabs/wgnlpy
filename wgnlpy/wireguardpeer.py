#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from .preshared_key import PresharedKey
from .public_key import PublicKey

class WireGuardPeer(object):
    __slots__ = (
        "public_key",
        "preshared_key",
        "endpoint",
        "persistent_keepalive_interval",
        "last_handshake_time",
        "rx_bytes",
        "tx_bytes",
        "allowedips",
        "protocol_version",
    )

    def __init__(self, peer, spill_preshared_keys=False):
        self.public_key = PublicKey(peer.get_attr('WGPEER_A_PUBLIC_KEY'))
        self.preshared_key = peer.get_attr('WGPEER_A_PRESHARED_KEY')
        if not spill_preshared_keys:
            self.preshared_key = self.preshared_key is not None
        else:
            self.preshared_key = PresharedKey(self.preshared_key)
        self.endpoint = peer.get_attr('WGPEER_A_ENDPOINT')
        self.persistent_keepalive_interval = peer.get_attr('WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL')
        self.last_handshake_time = peer.get_attr('WGPEER_A_LAST_HANDSHAKE_TIME')
        if not self.last_handshake_time > 0:
            self.last_handshake_time = None
        self.rx_bytes = peer.get_attr('WGPEER_A_RX_BYTES')
        self.tx_bytes = peer.get_attr('WGPEER_A_TX_BYTES')
        self.protocol_version = peer.get_attr('WGPEER_A_PROTOCOL_VERSION')

        self.allowedips = []
        for allowedip in peer.get_attr('WGPEER_A_ALLOWEDIPS') or []:
            self.allowedips.append(allowedip.network())

    def __repr__(self):
        return repr({
            'public_key': self.public_key,
            'preshared_key': self.preshared_key,
            'endpoint': self.endpoint,
            'persistent_keepalive_interval': self.persistent_keepalive_interval,
            'last_handshake_time': self.last_handshake_time,
            'rx_bytes': self.rx_bytes,
            'tx_bytes': self.tx_bytes,
            'allowedips': self.allowedips,
            'protocol_version': self.protocol_version,
        })

#
