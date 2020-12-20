#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from .key import Key

from base64 import b64decode
from hashlib import shake_128, blake2s
from ipaddress import ip_network, IPv4Network, IPv6Network
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

class PublicKey(Key):
    def __init__(self, key=None):
        if key is None:
            super().__init__()
        elif isinstance(key, PublicKey):
            super().__init__(key)
        elif isinstance(key, X25519PublicKey):
            super().__init__(key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ))
        elif isinstance(key, (bytes, bytearray)):
            super().__init__(X25519PublicKey.from_public_bytes(key).public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ))
        elif isinstance(key, str):
            super().__init__(X25519PublicKey.from_public_bytes(b64decode(key)).public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ))
        else:
            raise TypeError("key must be PublicKey, bytes, bytearray, or str")

    def __eq__(self, other):
        if isinstance(other, Key) and not isinstance(other, PublicKey):
            return NotImplemented

        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()

    def orchid(self, secret=b'', network=None):
        if network is None:
            return self.orchid6(secret)

        if isinstance(secret, str):
            secret = secret.encode('utf-8')
        elif not isinstance(secret, (bytes, bytearray)):
            secret = bytes(secret)

        if not isinstance(network, (IPv4Network, IPv6Network, )):
            network = ip_network(network)

        hash = shake_128(secret + bytes(self)).digest(network.max_prefixlen//8)
        mask = int.from_bytes(network.hostmask.packed, byteorder='big')
        host = int.from_bytes(hash, byteorder='big')
        addr = network[host & mask]

        if addr == network.network_address:
            addr += 1
        elif addr == network.broadcast_address:
            addr -= 1

        assert addr != network.network_address, "Generated network address"
        assert addr != network.broadcast_address, "Generated broadcast address"
        assert addr in network, "Generated out-of-network address"
        return addr

    def orchid4(self, secret=b''):
        return self.orchid(secret, IPv4Network("100.64.0.0/10"))

    def orchid6(self, secret=b''):
        return self.orchid(secret, IPv6Network("2001:20::/28"))


    def lla(self, secret=b'', network=None):
        if network is None:
            return self.lla6(secret)

        if isinstance(secret, str):
            secret = secret.encode('utf-8')
        elif not isinstance(secret, (bytes, bytearray)):
            secret = bytes(secret)

        if not isinstance(network, (IPv4Network, IPv6Network, )):
            network = ip_network(network)

        hash = blake2s(bytes(self),
            digest_size=32,
            key=secret,
            ).digest()[:network.max_prefixlen//8]
        mask = int.from_bytes(network.hostmask.packed, byteorder='big')
        host = int.from_bytes(hash, byteorder='big')
        addr = network[host & mask]

        if addr == network.network_address:
            addr += 1
        elif addr == network.broadcast_address:
            addr -= 1

        assert addr != network.network_address, "Generated network address"
        assert addr != network.broadcast_address, "Generated broadcast address"
        assert addr in network, "Generated out-of-network address"
        return addr

    def lla4(self, secret=b''):
        return self.lla(secret, IPv4Network("169.254.0.0/16"))

    def lla6(self, secret=b''):
        return self.lla(secret, IPv6Network("fe80::/10"))

#
