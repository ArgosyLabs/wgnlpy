#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense

from wgnlpy import WireGuard, PrivateKey, PresharedKey
from base64 import b64encode
from pprint import pprint

peer = PrivateKey.generate().public_key()
print("PEER", repr(peer))
print(peer.lla4())

wg = WireGuard()
interface = "wg-test"

wg.set_interface(interface, private_key=PrivateKey.generate(), replace_peers=True)

wg.set_peer(interface, peer,
    preshared_key=PresharedKey.generate(),
    endpoint="[::ffff:203.0.113.0%8]:12345",
    allowedips=["2001:db8::/32", "198.51.100.1"],
    )
peers = wg.get_interface(interface).peers
assert peer in peers

pprint(peers[peer])

wg.remove_peers(interface, peer)
assert peer not in wg.get_interface(interface).peers
