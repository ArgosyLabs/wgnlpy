#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from base64 import b64decode
from pyroute2.netlink import nla_base

class key(nla_base):
    fields = (
        ('value', 's'),
    )

    def encode(self):
        assert isinstance(self.value, (bytes, bytearray))
        assert 32 == len(self.value)
        self['value'] = self.value
        nla_base.encode(self)

    def decode(self):
        nla_base.decode(self)
        self.value = self['value'] if self['value'] != bytes(32) else None

    @staticmethod
    def frob(nitz):
        if not isinstance(nitz, (bytes, bytearray)):
            nitz = b64decode(nitz)

        return nitz

#
