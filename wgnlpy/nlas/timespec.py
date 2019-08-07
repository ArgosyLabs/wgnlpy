#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from math import modf
from pyroute2.netlink import nla_base

class timespec(nla_base):
    fields = (
        ('tv_sec', 'q'),
        ('tv_nsec', 'l'),
    )

    def encode(self):
        tv_sec, tv_nsec = modf(self.value)
        self['tv_sec'] = int(tv_sec)
        self['tv_nsec'] = int(tv_nsec * 1e9)
        nla_base.encode(self)

    def decode(self):
        nla_base.decode(self)
        tv_sec = int(self['tv_sec'])
        tv_nsec = int(self['tv_nsec']) / 1e9
        self.value = tv_sec + tv_nsec

#
