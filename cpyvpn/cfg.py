# -*- coding: utf-8 -*-
# Created on 30.11.2020
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import re
import json
import collections
from collections import abc


# CheckPoint Responce/Request format data handling
class CPRR(object):

    all_re = re.compile(r'(?P<w>[\n\t ]+)|' +
    r'(?P<h>\(([\w]+)\n)|' +
    r'(?P<s>:([\w]+| )[\s]*\(([^\(]*?)\))|' +
    r'(?P<m>:([\w]*)[^\(]\([^\n\)]*\n)|' +
    r'(?P<e>[\s]*\)\n)')

    def __init__(self, data):
        if isinstance(data, abc.Mapping):
            self.data = data
        else:
            self.deserialize(data)

    def root(self):
        return self._get_root()

    def _get_root(self):
        d = self.data
        return next(d.keys().__iter__())

    # Check if https requests returns 600 (OK) or not in ResponseHeader
    def status(self):
        top = self._get_root()
        rh = self.data[top].get("ResponseHeader")
        if rh:
            return int(rh["return_code"]) == 600

    def find(self, tag, data=None):
        d = self.data if data is None else data
        for k in d:
            v = d[k]
            if k == tag:
                return v
            if isinstance(v, abc.Mapping):
                ret = self.find(tag, v)
                if ret is not None:
                    return ret

    def _doparse(self):
        retd = collections.OrderedDict()
        retl = []

        while self._pos < self._dlen - 2:
            m = self.all_re.match(self._data, self._pos)
            if not m:
                raise IOError("Error parsing config data!")
            self._pos = m.span()[1]
            dct = m.groupdict()

            if dct["h"] is not None:
                tag = m.group(3)
                retd[tag] = self._doparse()

            elif dct["s"] is not None:
                tag = m.group(5)
                val = m.group(6).strip()
                if val and val[0] == '"' and val[-1] == '"':
                    val = val[1:-1]
                if tag == " ":
                    retl.append(val)
                else:
                    retd[tag] = val
            elif dct["m"] is not None:

                tag = m.group(8)
                val = self._doparse()

                if not tag:
                    retl.append(val)
                else:
                    retd[tag] = val
            elif dct["e"] is not None:
                break

        return retl if retl else retd

    def deserialize(self, data):
        self._pos = 0
        self._data = data
        self._dlen = len(data)
        self.data = self._doparse()

    @classmethod
    def _doserialize(cls, data, level):
        pref = "\t"*level
        ret = ""
        dataisseq = isinstance(data, (list, tuple))
        for k in data:
            if dataisseq:
                v = k
                k = ""
            else:
                v = data[k]
            isseq = isinstance(v, (list, tuple))
            if isinstance(v, abc.Mapping) or isseq:
                ret += "{}:{} (\n{}{})\n".format(pref, k, cls._doserialize(v, level + 1), pref)
            else:
                ret += "{}:{} ({})\n".format(pref, k, v)

        return ret

    def serialize(self):
        top = self._get_root()
        inner = self._doserialize(self.data[top], 1)
        return "({}\n{})\n\x00".format(top, inner)


class RRLib:

    def __init__(self, fp, patches={}):
        self._ccc_srv = {}
        self._ccc_clnt = {}
        self._slim = {}
        # with open(fnm, "rt") as fp:
        d = json.load(fp)
        for dct in d:
            rrtype = next(dct.keys().__iter__())
            if "clientRequest" in rrtype:
                crtype = dct[rrtype]["RequestHeader"]["type"]
                self._ccc_clnt[crtype] = dct
            elif "serverResponse" in rrtype:
                crtype = dct[rrtype]["ResponseHeader"]["type"]
                self._ccc_srv[crtype] = dct
            else:
                self._slim[rrtype] = dct

        for k, v in patches.items():
            path = k.split(".")
            first = path[0]

            if first in self._slim:
                dct = self.get_slim(first)
            else:
                ccctp, _, path = first.partition(":")
                if ccctp[0] == 'c':
                    dct = self.get_ccc_client(first)
                else:
                    dct = self.get_ccc_server(first)

            # NOTE: dict traversal only!
            for e in path[:-1]:
                if e in dct:
                    dct = dct[e]
                else:
                    dct = dct[e] = {}
            dct[path[-1]] = v

    def get_ccc_client(self, rt):
        return self._ccc_clnt[rt]

    def get_ccc_server(self, rt):
        return self._ccc_srv[rt]

    def get_slim(self, rt):
        return self._slim[rt]
