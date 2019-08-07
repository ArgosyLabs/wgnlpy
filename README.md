# wgnlpy
Python netlink connector to WireGuard
======

A simple control interface for [WireGuard](https://www.wireguard.com/) via
Netlink, written in Python.

```python
from wgnlpy import WireGuard

interface = "wg0"
peer = b'...'

wg = WireGuard()

wg.set_peer(interface, peer,
	endpoint="203.0.113.0:51820",
	allowedips=["2001:db8::/32"],
	)
assert peer in wg.get_interface(interface).peers

wg.remove_peers(interface, peer)
assert peer not in wg.get_interface(interface).peers
```

Requires [pyroute2](https://pyroute2.org/).

Also useful: the `sockaddr_in` and `sockaddr_in6` utility classes for
sockaddr manipulation.

License: [MIT](https://opensource.org/licenses/MIT)
