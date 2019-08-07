#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense

from wgnlpy import WireGuard
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from base64 import b64encode
from pprint import pprint

peer = X25519PrivateKey.generate().private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
print("PEER", b64encode(peer).decode('utf-8'))

wg = WireGuard()
interface = "wg-test"

wg.set_peer(interface, peer,
	endpoint="[::ffff:203.0.113.0%8]:12345",
	allowedips=["2001:db8::/32", "198.51.100.1"],
	)
peers = wg.get_interface(interface).peers
assert peer in peers

pprint(peers[peer])

wg.remove_peers(interface, peer)
assert peer not in wg.get_interface(interface).peers
