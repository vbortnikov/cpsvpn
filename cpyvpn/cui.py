# coding: utf-8
# Created on 28.05.2021
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import struct
import getpass
import os
import logging

logger = logging.getLogger()


# Simple terminal interactive wrapper for data input
class TUI:

    @staticmethod
    def drop_colon(pref):
        pref = pref.strip()
        if pref[-1] == ":":
            pref = pref[:-1]
        return pref

    def print_header(self, h):
        if h:
            print(h)
        return h

    def ask_str(self, pref):
        return input(self.drop_colon(pref) + ": ")

    def ask_pwd(self, pref):
        # 1) password by hand
        return getpass.getpass(self.drop_colon(pref) + ": ")
        # 2) password from file ($HOME/auth_pochta)
        #with open(os.path.expanduser("~") + '/auth_pochta', 'r') as file:
        #    return file.read().rstrip()
        # 3) inline password
        #return "MY_PASSWORD"
    def ask_sel(self, pref, lst):
        print(pref)
        for i, tpl in enumerate(lst):
            print(i + 1, tpl[1])
        while 1:
            inp = input("Index [1-{}]:".format(i + 1))
            if not inp:
                return lst[0][0]
            try:
                idx = int(inp) - 1
                return lst[idx][0]
            except ValueError:
                continue

    def wait_input(self, lst):
        return lst


# Pipe-based input for use with external programs
# It gathers all input, encodes and sends to stdout, reads stdin, stops if '>' is not first char in the user input.
class PUI:
    sl = struct.Struct("!H")

    class Param:
        (HEADER, TEXT, PWD, CHOISE) = range(4)

        def __init__(self, qtype, query, choises=None):
            self.qtype = qtype
            self.query = query
            self.choises = choises

    def __init__(self, lh=None):
        self.lh = lh

    def print_header(self, h):
        return self.Param(self.Param.HEADER, h)

    def ask_str(self, pref):
        return self.Param(self.Param.TEXT, pref)

    def ask_pwd(self, pref):
        return self.Param(self.Param.PWD, pref)

    def ask_sel(self, pref, lst):
        return self.Param(self.Param.CHOISE, pref, lst)

    def _input(self):
        if self.lh:
            # len
            n = self.sl.unpack(self.lh.sock.recv(self.sl.size))[0]
            return self.lh.sock.recv(n).decode()
        else:
            return input()

    def wait_input(self, lst):
        req = "REQ:{} ".format(len(lst))
        for qe in lst:
            choises = ""
            if qe.choises and len(qe.choises) > 1:
                choises += str(len(qe.choises)) + " "
                choises += " ".join(("'{}' '{}'".format(key, txt) for key, txt in qe.choises))
            query = qe.query
            if qe.qtype == self.HEADER:
                tag = "h"
                query = qe.query.replace("'", "\\'")
            else:
                tag = qe.query.replace(" ", "_").replace("-", "_")
            req += "{} {} '{}' {}".format(qe.qtype, tag.lower(), query, choises)
        logger.info(req)
        ret = []
        for qe in lst:
            s = self._input()
            if s[0] == ">":
                val = s[1:]
                if qe.choises and len(qe.choises) > 1:
                    try:
                        val = int(val)
                        val = qe.choises[val][0]
                    except ValueError:
                        for k, t in qe.choises:
                            if val == k or val == t:
                                val = k
                                break
                ret.append(val)
            else:
                raise IOError("End of input recieved!")
        return ret
