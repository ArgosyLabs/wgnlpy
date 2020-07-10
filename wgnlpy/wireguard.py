#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from pyroute2 import netlink

from .preshared_key import PresharedKey
from .private_key import PrivateKey
from .public_key import PublicKey
from .wireguardinfo import WireGuardInfo

class WireGuard(object):
    __slots__ = ( "__socket" )

    from .nlas import device as __device

    def __init__(self, **kwargs):
        self.__socket = netlink.generic.GenericNetlinkSocket()
        self.__socket.bind('wireguard', self.__device)

    def __del__(self):
        self.__socket.close()

    def __get(self, device):
        flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
        return self.__socket.nlm_request(device, msg_type=self.__socket.prid, msg_flags=flags)

    def __set(self, device):
        flags = netlink.NLM_F_ACK | netlink.NLM_F_REQUEST
        return self.__socket.nlm_request(device, msg_type=self.__socket.prid, msg_flags=flags)

    def get_interface(self, interface, spill_private_key=False, spill_preshared_keys=False):
        device = self.__device.get_device(interface)
        messages = self.__get(device)

        return WireGuardInfo(messages, spill_private_key, spill_preshared_keys)

    def set_interface(self, interface,
            private_key=None,
            listen_port=None,
            fwmark=None,
            replace_peers=False,
            ):

        device = self.__device.set_device(interface)

        if replace_peers:
            device['attrs'].append(('WGDEVICE_A_FLAGS', device.flag.REPLACE_PEERS.value))

        if private_key is not None:
            if isinstance(private_key, PrivateKey):
                private_key = bytes(private_key)
            elif not isinstance(private_key, (bytes, bytearray)):
                private_key = bytes(PrivateKey(private_key))
            device['attrs'].append(('WGDEVICE_A_PRIVATE_KEY', private_key))

        if listen_port is not None:
            device['attrs'].append(('WGDEVICE_A_LISTEN_PORT', listen_port))

        if fwmark is not None:
            device['attrs'].append(('WGDEVICE_A_FWMARK', fwmark))

        return self.__set(device)

    def remove_peers(self, interface, *public_keys):
        device = self.__device.set_device(interface)
        device['attrs'].append(('WGDEVICE_A_PEERS', []))

        for public_key in public_keys:
            peer = self.__device.peer()
            if isinstance(public_key, PublicKey):
                public_key = bytes(public_key)
            elif not isinstance(public_key, (bytes, bytearray)):
                public_key = bytes(PublicKey(public_key))
            peer['attrs'].append(('WGPEER_A_PUBLIC_KEY', public_key))
            peer['attrs'].append(('WGPEER_A_FLAGS', peer.flag.REMOVE_ME.value))
            device.get_attr('WGDEVICE_A_PEERS').append({'attrs': peer['attrs']})

        return self.__set(device)

    def set_peer(self, interface, public_key,
            preshared_key=None,
            endpoint=None,
            persistent_keepalive_interval=None,
            allowedips=None,
            replace_allowedips=None,
            update_only=False,
            ):

        device = self.__device.set_device(interface)

        peer = device.peer()
        if isinstance(public_key, PublicKey):
            public_key = bytes(public_key)
        elif not isinstance(public_key, (bytes, bytearray)):
            public_key = bytes(PublicKey(public_key))
        peer['attrs'].append(('WGPEER_A_PUBLIC_KEY', public_key))

        if replace_allowedips is None and allowedips is not None:
            replace_allowedips = True

        flags = 0
        if replace_allowedips:
            flags |= peer.flag.REPLACE_ALLOWEDIPS.value
        if update_only:
            flags |= peer.flag.UPDATE_ONLY.value
        if flags:
            peer['attrs'].append(('WGPEER_A_FLAGS', flags))

        if preshared_key is not None:
            if isinstance(preshared_key, PresharedKey):
                preshared_key = bytes(preshared_key)
            elif not isinstance(preshared_key, (bytes, bytearray)):
                preshared_key = bytes(PresharedKey(preshared_key))
            peer['attrs'].append(('WGPEER_A_PRESHARED_KEY', preshared_key))

        if endpoint is not None:
            peer['attrs'].append(('WGPEER_A_ENDPOINT', self.__device.peer.sockaddr.frob(endpoint)))

        if persistent_keepalive_interval is not None:
            peer['attrs'].append(('WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL', persistent_keepalive_interval))

        if allowedips is not None:
            peer['attrs'].append(('WGPEER_A_ALLOWEDIPS', []))

            for allowedip in allowedips:
                peer.get_attr('WGPEER_A_ALLOWEDIPS').append({'attrs': self.__device.peer.allowedip.frob(allowedip)['attrs']})

        device['attrs'].append(('WGDEVICE_A_PEERS', [{'attrs': peer['attrs']}]))
        return self.__set(device)

    def replace_allowedips(self, interface, *public_keys):
        device = self.__device.set_device(interface)
        device['attrs'].append(('WGDEVICE_A_PEERS', []))

        for public_key in public_keys:
            peer = self.__device.peer()
            if isinstance(public_key, PublicKey):
                public_key = bytes(public_key)
            elif not isinstance(public_key, (bytes, bytearray)):
                public_key = bytes(PublicKey(public_key))
            peer['attrs'].append(('WGPEER_A_PUBLIC_KEY', public_key))
            peer['attrs'].append(('WGPEER_A_FLAGS', peer.flag.REPLACE_ALLOWEDIPS.value))
            device.get_attr('WGDEVICE_A_PEERS').append({'attrs': peer['attrs']})

        return self.__set(device)

#
