#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from pyroute2 import netlink

class WireGuard(object):
    from .nlas import device as __device

    def __init__(self, **kwargs):
        self.__socket = netlink.generic.GenericNetlinkSocket()
        self.__socket.bind('wireguard', self.__device)

    def __get(self, device):
        flags = netlink.NLM_F_ACK | netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
        return self.__socket.nlm_request(device, msg_type=self.__socket.prid, msg_flags=flags)

    def __set(self, device):
        flags = netlink.NLM_F_ACK | netlink.NLM_F_REQUEST
        return self.__socket.nlm_request(device, msg_type=self.__socket.prid, msg_flags=flags)

    def get_interface(self, interface, spill_private_key=False, spill_preshared_keys=False):
        device = self.__device.get_device(interface)
        messages = self.__get(device)

        class WireGuardInfo(object):
            def __init__(self, messages, spill_private_key, spill_preshared_keys):
                self.ifindex = messages[0].get_attr('WGDEVICE_A_IFINDEX')
                self.ifname = messages[0].get_attr('WGDEVICE_A_IFNAME')
                private_key = messages[0].get_attr('WGDEVICE_A_PRIVATE_KEY')
                if not spill_private_key:
                    private_key = private_key is not None
                self.private_key = private_key
                self.public_key = messages[0].get_attr('WGDEVICE_A_PUBLIC_KEY')
                self.listen_port = messages[0].get_attr('WGDEVICE_A_LISTEN_PORT')
                self.fwmark = messages[0].get_attr('WGDEVICE_A_FWMARK')

                self.peers = { }

                for message in messages:
                    for peer in message.get_attr('WGDEVICE_A_PEERS') or []:
                        public_key = peer.get_attr('WGPEER_A_PUBLIC_KEY')
                        assert public_key is not None
                        if public_key not in self.peers:
                            preshared_key = peer.get_attr('WGPEER_A_PRESHARED_KEY')
                            if not spill_preshared_keys:
                                preshared_key = preshared_key is not None
                            self.peers[public_key] = {
                                'preshared_key': preshared_key,
                                'endpoint': peer.get_attr('WGPEER_A_ENDPOINT'),
                                'persistent_keepalive_interval': peer.get_attr('WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL'),
                                'last_handshake_time': peer.get_attr('WGPEER_A_LAST_HANDSHAKE_TIME'),
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
            device['attrs'].append(('WGDEVICE_A_PRIVATE_KEY', device.key.frob(private_key)))

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
            peer['attrs'].append(('WGPEER_A_PUBLIC_KEY', peer.key.frob(public_key)))
            peer['attrs'].append(('WGPEER_A_FLAGS', peer.flag.REMOVE_ME.value))
            device.get_attr('WGDEVICE_A_PEERS').append(peer)

        return self.__set(device)

    def set_peer(self, interface, public_key,
            preshared_key=None,
            endpoint=None,
            persistent_keepalive_interval=None,
            allowedips=None,
            replace_allowedips=None,
            ):

        device = self.__device.set_device(interface)

        peer = device.peer()
        peer['attrs'].append(('WGPEER_A_PUBLIC_KEY', peer.key.frob(public_key)))

        if replace_allowedips is None and allowedips is not None:
            replace_allowedips = True

        if replace_allowedips:
            peer['attrs'].append(('WGPEER_A_FLAGS', peer.flag.REPLACE_ALLOWEDIPS.value))

        if preshared_key is not None:
            peer['attrs'].append(('WGPEER_A_PRESHARED_KEY', peer.key.frob(preshared_key)))

        if endpoint is not None:
            peer['attrs'].append(('WGPEER_A_ENDPOINT', self.__device.peer.sockaddr.frob(endpoint)))

        if persistent_keepalive_interval is not None:
            peer['attrs'].append(('WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL', persistent_keepalive_interval))

        if allowedips is not None:
            peer['attrs'].append(('WGPEER_A_ALLOWEDIPS', []))

            for allowedip in allowedips:
                peer.get_attr('WGPEER_A_ALLOWEDIPS').append(self.__device.peer.allowedip.frob(allowedip))

        device['attrs'].append(('WGDEVICE_A_PEERS', [peer]))
        return self.__set(device)

    def replace_allowedips(self, interface, *public_keys):
        device = self.__device.set_device(interface)
        device['attrs'].append(('WGDEVICE_A_PEERS', []))

        for public_key in public_keys:
            peer = self.__device.peer()
            peer['attrs'].append(('WGPEER_A_PUBLIC_KEY', peer.key.frob(public_key)))
            peer['attrs'].append(('WGPEER_A_FLAGS', peer.flag.REPLACE_ALLOWEDIPS.value))
            device.get_attr('WGDEVICE_A_PEERS').append(peer)

        return self.__set(device)

#
