# -*- coding: utf-8 -*-
# Created on 15.05.2021
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import io
import re
import datetime

# INFO:
# https://en.wikipedia.org/wiki/X.690
# http://handle.itu.int/11.1002/1000/14472-en?locatt=format:pdf&auth
# http://handle.itu.int/11.1002/1000/14468-en?locatt=format:pdf&auth
#
# https://datatracker.ietf.org/doc/html/rfc5280
# https://datatracker.ietf.org/doc/html/rfc2797
# http://luca.ntop.org/Teaching/Appunti/asn1.html


# Simple read-only der parsing
class DERType:

    def __init__(self, s):

        mask = 0x1f
        o1 = ord(s.read(1))
        tag = o1 & mask
        if tag == mask:
            tag = 0
            i = 0
            while True:
                o1 = ord(s.read(1))
                tag |= (o1 & 0x7f) << (8 * i)
                i += 1
                if not o1 >> 7:
                    break

        cls = o1 >> 6
        self.cls = cls
        self.tag = tag
        self.c = (o1 >> 5) & 1

    def univ(self):
        return self.cls == 0

    def eoc(self):
        return self.tag == 0 and self.univ()


class DERSize:

    def __init__(self, s):

        mask = 0x7f
        o1 = ord(s.read(1))
        form = o1 >> 7
        data = o1 & mask
        if form == 0:
            self.size = data
        else:
            if data == 127:
                raise NotImplementedError("Reserved form encountered!")
            elif data == 0:
                l = -1
            else:
                l = 0
                for i in range(data):
                    d = ord(s.read(1))
                    l |= d << (8 * (data - i - 1))
            self.size = l

    def undef(self):
        return self.size == -1


class DERData:
    OCTET_STRING = 4
    OBJECT_IDENTIFIER = 6
    UTCTime = 23
    GTime = 24

    def __init__(self, s, parent=None):
        self.parent = parent
        self.sub = []
        self.dt = DERType(s)
        self.ds = DERSize(s)
        l = self.ds.size
        pos = s.tell()
        if self.dt.c:
            while True:
                if not self.ds.undef() and s.tell() - pos >= l:
                    break
                o = DERData(s, self)
                if (self.ds.undef() and o.eoc()):
                    break
                self.sub.append(o)
        else:
            self.data = s.read(self.ds.size)

    def __getitem__(self, key):
        return self.sub[key]

    def get_os(self):
        return self.data

    def get_utime(self):
        # strptime handles full range from 0 to 99
        # xx=68-99 ->19xx
        # xx=00-67 -> 20xx
        data = self.data.decode()
        fmt1 = '%y%m%d%H%M%S%z'
        fmt2 = '%y%m%d%H%M%z'
        try:
            return datetime.datetime.strptime(data, fmt1)
        except ValueError:
            # try local time, just in case
            return datetime.datetime.strptime(data, fmt2)

    def get_gtime(self):
        data = self.data.decode()
        data = data.replace(",", ".")
        # "fix" for zero-year?
        if data.startswith("0000"):
            data = "2000" + data[4:]
        dot = "." in data

        tz = re.search("[\+\-Z]", data)
        if tz:
            if tz.group() in ["-", "+"]:
                if len(data) - tz.end() == 2:
                    data += "00"

        fmtbase = '%y%m%d%H%M%S'
        for i in range(3):
            fmt = fmtbase[:2 * i]
            if dot:
                fmt += ".%f"
            if tz:
                fmt += "%z"
            try:
                gtime = datetime.datetime.strptime(data, fmt)
                if dot:
                    fr = gtime.microsecond / 1000000
                    if i == 1:
                        gtime = gtime.replace(second=int(60 * fr))
                    elif i == 2:
                        gtime = gtime.replace(minute=int(60 * fr))
            except ValueError:
                continue
            return gtime

    def get_time(self):
        return self.get_utime() if self.is_utime() else self.get_gtime() if self.is_gtime() else None

    def get_oid(self):
        # T-REC-X.690-202102

        id12 = self.data[0]
        oid = []
        oid.append(id12 // 40)
        oid.append(id12 % 40)

        val = None
        for i in range(1, self.ds.size):
            e = self.data[i]
            if e >> 7:
                e = e & 0x7f
                # First Long
                if val is None:
                    val = e
                else:
                    # Next Long
                    val <<= 7
                    val |= e
            else:
                # Short
                if val is not None:
                    # Last one
                    val <<= 7
                    val |= e
                    oid.append(val)
                    val = None
                else:
                    # Single
                    oid.append(e)

        return oid

    def is_os(self):
        return self.dt.tag == self.OCTET_STRING and self.dt.univ()

    def is_oid(self):
        return self.dt.tag == self.OBJECT_IDENTIFIER and self.dt.univ()

    def is_utime(self):
        return self.dt.tag == self.UTCTime  and self.dt.univ()

    def is_gtime(self):
        return self.dt.tag == self.GTime  and self.dt.univ()

    def iter(self):
        yield self
        for e in self.sub:
            yield from e.iter()


class Cert:
    # rfc2459 4.2.1  Standard Extensions

    # rfc3280
    # TODO: Standard Extensions
    # 4.2.2  Private Internet Extensions
    # 4.2.2.1  Authority Information Access
    # id-pkix  ::= { iso(1) identified-organization(3) dod(6) internet(1)
    #                       security(5) mechanisms(5) pkix(7) }
    # id-pe  ::=  { id-pkix 1 }
    # id-pe-authorityInfoAccess ::= { id-pe 1 }

    # PKIX -pe-authorityInfoAccess
    authorityInfoAccess = [1, 3, 6, 1, 5, 5, 7, 1, 1]
    # caIssuers (PKIX subject/authority info access descriptor
    caIssuers = [1, 3, 6, 1, 5, 5, 7, 48, 2]

    def __init__(self, s):
        self.root = DERData(s)

    def find_oid_parent(self, oid):
        prev = None
        for o in self.root.iter():
            if o.is_oid() and o.get_oid() == oid:
                break
            prev = o
        return prev

    def aia_urls(self):
        ret = []
        aia_node = self.find_oid_parent(self.authorityInfoAccess)
        if aia_node:
            for e in aia_node.sub:
                if e.is_os():
                    aia_data = DERData(io.BytesIO(e.data))
                    for aias in aia_data.sub:
                        if aias.sub[0].get_oid() == self.caIssuers:
                            ret.append(aias.sub[1].data.decode())
        return ret

    def get_notafter(self):
        return self.root.sub[0].sub[4].sub[1]
