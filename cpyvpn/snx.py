# coding: utf-8
# Created on 07.05.2021
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
from . import trutils
from . import cfg, utils

import logging

logger = logging.getLogger()


# Small helper to dispatch incoming data and command packets
class SNX(trutils.FramedTransportMixin, asyncio.Protocol):

    KA_msg = cfg.CPRR({"keepalive":{"id":0}}).serialize()

    def __init__(self, vna):
        super(SNX, self).__init__()
        self.vna = vna

    def process_incoming(self, data, dtype):
        if dtype == self.PACKET:
            if self.vna.tun_up():
                self.vna.tundev().write(data)
        else:
            data=utils.as_text(data)
            logging.debug("SNX incoming:\n{}".format(data))
            rr = cfg.CPRR(data)
            hndl_name = rr.root()
            h = getattr(self, hndl_name, None)
            if h is not None:
                h(rr)
            else:
                logger.warn("Unhandled incoming command: {}".format(data))
