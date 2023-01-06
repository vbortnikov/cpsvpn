# coding: utf-8
# Created on 07.05.2021
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import struct
import logging
from . import utils

logger = logging.getLogger()


class TransportBase:

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.on_connection_lost(exc)

    def on_connection_lost(self, exc):
        pass


# SSL/TCP variant
class FramedTransportMixin(TransportBase):
    CMD = 1
    PACKET = 2
    ESPT = 4
    TLS = 0
    HDR = -1
    hdr = struct.Struct("!II")
    tls_hdr = struct.Struct("!BHH")

    @classmethod
    def tls_len(cls, data):
        hdr = cls.tls_hdr.unpack_from(data[:cls.tls_hdr.size])
        return hdr[-1]

    def __init__(self):

        self._nbytes = 0
        self._dt = None
        self._bytes = bytes()

    def data_received(self, data):
        if not data:
            return

        first_char = data[0]


        while data:
            if self._nbytes == 0:

                self._dt = self.HDR
                first_char = data[0]
                #CP record starts with 0, TLS - with 0×14..0×18
                if not (first_char == 0 or (first_char >= 0x14 and first_char <= 0x18)):
                    raise ValueError("Invalid first header byte {}!".format(hex(first_char)))
                if first_char != 0:
                    self._nbytes = self.tls_hdr.size
                else:
                    self._nbytes = self.hdr.size

            nread = len(self._bytes)
            rest = self._nbytes - nread
            self._bytes += data[:rest]
            data = data[rest:]

            if self._nbytes == len(self._bytes):
                if self._dt == self.HDR:
                    if self._nbytes == self.tls_hdr.size:
                        self._dt = self.TLS
                        self._nbytes += self.tls_len(self._bytes)
                    else:
                        self._nbytes, self._dt = self.hdr.unpack_from(self._bytes)
                        self._bytes = bytes()
                else:
                    self.process_incoming(self._bytes, self._dt)
                    self._nbytes = 0
                    self._bytes = bytes()

    def send_data(self, data, dtype):
        data = utils.as_bytes(data)
        dlen = len(data)
        if dtype == self.TLS:
            self.transport.write(data)
        else:
            hdr = self.hdr.pack(dlen, dtype)
            self.transport.write(hdr + data)

    def send_packet(self, data):
        self.send_data(data, self.PACKET)

    def send_cmd(self, data):
        self.send_data(data, self.CMD)

    def send_tls(self, data):
        self.send_data(data, self.TLS)
