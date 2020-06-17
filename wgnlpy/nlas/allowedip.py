#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from socket import AF_INET, AF_INET6
from ipaddress import IPv4Network, IPv6Network, ip_network
from pyroute2.netlink import nla, NLA_F_NESTED

class allowedip(nla):
    nla_flags = NLA_F_NESTED
    nla_map = (
        ('WGALLOWEDIP_A_UNSPEC', 'none'),
        ('WGALLOWEDIP_A_FAMILY', 'uint16'),
        ('WGALLOWEDIP_A_IPADDR', 'cdata'),
        ('WGALLOWEDIP_A_CIDR_MASK', 'uint8'),
    )

    def network(self):
        family, ipaddr, cidr_mask = (
            self.get_attr('WGALLOWEDIP_A_FAMILY'),
            self.get_attr('WGALLOWEDIP_A_IPADDR'),
            self.get_attr('WGALLOWEDIP_A_CIDR_MASK'),
        )

        try:
            return {
                AF_INET: IPv4Network,
                AF_INET6: IPv6Network,
            }[family](ipaddr, cidr_mask)
        except:
            raise NotImplementedError

    @staticmethod
    def frob(nitz):
        self = allowedip()

        if not isinstance(nitz, (IPv4Network, IPv6Network)):
            nitz = ip_network(nitz)

        if isinstance(nitz, IPv4Network):
            self['attrs'].append(('WGALLOWEDIP_A_FAMILY', AF_INET.value))
        elif isinstance(nitz, IPv6Network):
            self['attrs'].append(('WGALLOWEDIP_A_FAMILY', AF_INET6.value))
        else:
            raise NotImplementedError

        self['attrs'].append(('WGALLOWEDIP_A_IPADDR', nitz.network_address.packed))
        self['attrs'].append(('WGALLOWEDIP_A_CIDR_MASK', nitz.prefixlen))

        return self

#
