# coding: utf-8
# Created on 30.11.2020
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import shlex
import socket
import signal
import subprocess
import fcntl
import ctypes
import logging
from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI
from pyroute2 import IPRoute

from . import utils

logger = logging.getLogger()

# Linux specific block
IFNAMSIZ = 16
sin_addr_t = ctypes.c_byte * 4


def gen_ranges(ip_min, ip_max):
    mask32 = 0xffffffff
    ret = []
    ip = ip_min
    while ip <= ip_max:

        # make mask that covers full or part  of given range, but does not exceed it
        mask = 0
        for imask in range(32):
            curbit = 1 << imask
            mask |= curbit
            ip_low = ip & (~mask) & mask32
            ip_high = ip_low | mask
            if ip_low < ip or ip_high > ip_max:
                mask &= ~curbit & mask32
                break
        ret.append((utils.ipint2str(ip), 32 - mask.bit_length(), utils.ipint2str(~mask & mask32)))
        ip += mask + 1
    return ret


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),  # sin_family
                ("sin_port", ctypes.c_ushort),
                ("sin_addr", sin_addr_t),
                ("__pad", ctypes.c_byte * 8)]  # struct sockaddr_in is 16 bytes


class ifmap(ctypes.Structure):
    _fields_ = [
        ("mem_start", ctypes.c_ulong),
        ("mem_end", ctypes.c_ulong),
        ("base_addr", ctypes.c_short),
        ("irq", ctypes.c_byte),
        ("dma", ctypes.c_byte),
        ("port", ctypes.c_byte)
    ]


class ifr_ifrn(ctypes.Structure):
    _fields_ = [("ifrn_name", ctypes.c_char * IFNAMSIZ)]


class ifr_ifru(ctypes.Union):
    _fields_ = [
        ("ifru_addr", sockaddr),
        ("ifru_dstaddr", sockaddr),
        ("ifru_broadaddr", sockaddr),
        ("ifru_netmask", sockaddr),
        ("ifru_hwaddr", sockaddr),

        ("ifru_flags", ctypes.c_short),
        ("ifru_ivalue", ctypes.c_int),
        ("ifru_mtu", ctypes.c_int),

        ("ifru_map", ifmap),
        #         char ifru_slave[IFNAMSIZ];      /* Just fits the size */
        ("ifru_slave", ctypes.c_char * IFNAMSIZ),
        ("ifru_newname", ctypes.c_char * IFNAMSIZ),
        ("ifru_data", ctypes.c_void_p),
    ]


class ifreq(ctypes.Structure):
    _fields_ = [
        ("ifr_ifrn", ifr_ifrn),
        ("ifr_ifru", ifr_ifru),
    ]


class TunTapDevicePy:
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    IFF_UP = 1 << 0

    #     TUNSETIFF=_IOW('T', 202, "int")
    TUNSETIFF = 0x400454ca

    def __init__(self, name="", dev="/dev/net/tun", tun=True, nopi=True, mtu=1500):
        self.fd = fd = os.open(dev, os.O_RDWR)
        self.f = open(fd, 'rb+', buffering=0)

        try:
            name = name.encode("latin1")
        except AttributeError:
            pass
        # in VNANM.__init__. we run (run_nmcli(["add", "type", "tun"...
        req = ifreq()
        flags = self.IFF_TUN if tun else self.IFF_TAP
        if nopi:
            flags |= self.IFF_NO_PI
        req.ifr_ifrn.ifrn_name = name
        req.ifr_ifru.ifru_flags = flags
        reqba = bytearray(req)
        if fcntl.ioctl(fd, self.TUNSETIFF, reqba):
            raise RuntimeError("ioctl failed!")

        reqret = ifreq.from_buffer(reqba)
        self.name = reqret.ifr_ifrn.ifrn_name
        if name and name != self.name:
            raise RuntimeError("Bad iface name!")
        self.mtu = mtu

    def read(self):
        return self.f.read(self.mtu)

    def write(self, data):
        return self.f.write(data)

    def fileno(self):
        return self.fd

    def close(self):
        self.f.close()


# Use  Network Manager to setup tun in user mode (without root)
# https://mail.gnome.org/archives/networkmanager-list/2016-January/msg00053.html

# class wrapper for c code (no way using as base class)
# need it because read() function signature is different in pytun and cpyvpn
class TunTapDeviceCpp():
    def __init__(self, dev_name):
        # TunTapDevice(name='', flags=IFF_TUN, dev='/dev/net/tun')
        self.tun_dev = TunTapDevice(name=dev_name, flags=IFF_TUN | IFF_NO_PI)
        self.f = open(self.fileno(), 'rb+', buffering=0)

    def read(self):  # argument mismatch so we need override and incapsulate
        return self.f.read(self.tun_dev.mtu)

    def write(self, data):
        return self.f.write(data)

    def fileno(self):
        return self.tun_dev.fileno()

    def close(self):
        self.tun_dev.close()


# ====  VNA classes =====
class VNABase(object):

    def __init__(self, up_on_init=False):
        self.addr = None
        self.is_up = up_on_init

    def set_ips(self, addr, gw):
        self.addr = addr
        self.gw = gw

    def om_ip(self):
        return self.addr

    def set_dns(self, ips, domains):
        MAXNS = 3
        ns = 0
        try:
            with open("/etc/resolv.conf", "rt") as resolv:
                for l in resolv:
                    if "nameserver" in l:
                        ns += 1
        except:
            pass
        ips = ips[:max(0, MAXNS - ns)]
        self._set_dns(ips, domains)

    def tun_up(self):
        return self.is_up

    def tundev(self):
        return self.dev

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.down()


__def_snx_name__ = "tunsnx"
#__def_snx_name__ = "tunsnx%d" # to get unique names like tunsnx0

STDOUT = subprocess.STDOUT
PIPE = subprocess.PIPE
DEVNULL = subprocess.DEVNULL


class VNASD(VNABase):  # implementation for systemd-networkd
    def __init__(self, args):
        logger.debug(f"VNASD: __init__({args})")
        super(VNASD, self).__init__()
        self.dev = TunTapDeviceCpp(args.get("interface", __def_snx_name__))
        self.name = self.dev.tun_dev.name
        self.dev.tun_dev.mtu = args.get("mtu", 1350)

    def down(self):
        logger.debug("VNASD: down()")
        self.dev.tun_dev.down()
        self.is_up = False

    def up(self):
        logger.debug("VNASD: up()")
        if self.is_up:
            self.down()
        self.dev.tun_dev.up()
        self.is_up = True

    def set_ips(self, addr, gw):
        logger.debug(f"VNASD: set_ips({addr},{gw})")
        VNABase.set_ips(self, addr, gw)
        self.dev.tun_dev.addr = addr

    def set_dns(self, ips, domains):  # TODO: find another way for dns, DBUS ?
        logger.debug(f"VNASD: set_dns({ips},{domains})")
        cmd = f"sudo resolvectl dns {self.name} {' '.join(ips)} && sudo resolvectl domain {self.name} {' '.join(domains)}"
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, check=True)

    def set_routes(self, routes):
        logger.debug(f"VNASD: set_routes({routes})")
        with IPRoute() as ipr:
            for route in routes:
                for ip, masklen, _ in gen_ranges(utils.ipstr2int(route[0]), utils.ipstr2int(route[1])):
                    logger.debug("VNASD: adding route {}/{} dev {}".format(ip, masklen, self.name))
                    ipr.route('add', dst="{}/{}".format(ip, masklen), oif=ipr.link_lookup(ifname=self.name),
                              scope='link')


class VNANM(VNABase):
    @staticmethod
    def run_nmcli(cmd, opt=[]):
        cmd = ["nmcli", "-c", "no", "-t"] + opt + ["c"] + cmd
        ret = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
        return ret.stdout

    def __init__(self, args):
        super(VNANM, self).__init__()
        self.name = name = args.get("interface", __def_snx_name__)
        self.tun = tun = args.get("tun", True)
        self.nopi = nopi = args.get("nopi", True)
        self.mtu = mtu = args.get("mtu", 1500)

        uid = os.getuid()
        newtun = True
        ntun = 0
        for l in self.run_nmcli(["s"]).split("\n"):
            if l.partition(":")[0] == name:
                ntun += 1
        if ntun == 1:
            ret = self.run_nmcli(["s", self.name])
            for l in ret.split("\n"):
                if "owner" in l:
                    tunuid = int(l.partition(":")[2])
                    if uid == tunuid:
                        newtun = False
                        break
        if newtun:
            if ntun != 0:
                self.run_nmcli(["del", self.name])
            self.run_nmcli(
                ["add", "type", "tun", "ifname", name, "con-name", name, "mode", "tun" if tun else "tap", "tun.pi",
                 "no" if nopi else "yes",
                 "owner", str(uid), "autoconnect", "no", "ip4", "0.0.0.0"])
        self.set_mtu(mtu)

        self.run_nmcli(["up", self.name])
        self._init_dev()
        self.down()

    def _init_dev(self):
        self.dev = TunTapDevicePy(self.name, tun=self.tun, nopi=self.nopi, mtu=self.mtu)

    def set_mtu(self, mtu):
        self.run_nmcli(["mod", self.name, "ethernet.mtu", str(mtu)])

    def _set_dns(self, ips, domains):
        allips = " ".join(ips)
        if ips:
            self.run_nmcli(["mod", self.name, "ipv4.dns", allips])
            self.run_nmcli(["mod", self.name, "ipv4.dns-priority", "50"])  # NM default for VPN
            if domains:
                self.run_nmcli(["mod", self.name, "ipv4.dns-search", " ".join(domains)])

    def set_routes(self, routes):
        self.routes = routes
        lst = []
        for itm in routes:
            for ip, masklen, _ in gen_ranges(utils.ipstr2int(itm[0]), utils.ipstr2int(itm[1])):
                addr = "{}/{}".format(ip, masklen)
                lst.append(addr)
        all_routes = ",".join(lst)
        self.run_nmcli(["mod", self.name, "ipv4.routes", all_routes])

    def down(self):
        if self.run_nmcli(["show", self.name], ["-f", "GENERAL.STATE"]):
            self.run_nmcli(["down", self.name])
            self.dev.close()
        self.is_up = False

    def up(self):
        self.down()
        self.run_nmcli(["mod", self.name, "ipv4.addresses", self.addr])

        self.run_nmcli(["up", self.name])
        self._init_dev()
        self.is_up = True


class VNAVPNC(VNABase):

    def __init__(self, args):
        self._vpnc = args.get("script")
        if not self._vpnc:
            raise RuntimeError("vpnc script name not set!")
        super(VNAVPNC, self).__init__()
        self._uid = args.get("uid")  # !
        self._name = args.get("interface", __def_snx_name__)
        self._env = {"VPNPID": str(os.getpid()), "TUNDEV": self._name, "INTERNAL_IP4_MTU": "1500"}

        self.run_vpnc("pre-init")

        self.dev = TunTapDevicePy(self._name)

    def run_vpnc(self, reason):
        env = dict(self._env)
        env.update({"reason": reason})
        # kw = {"env":env, "stdin":DEVNULL, "stdout":DEVNULL, "stderr":STDOUT, "check":True}
        kw = {"env": env, "stdin": DEVNULL, "stdout": STDOUT, "stderr": STDOUT, "check": True}
        subprocess.run([self._vpnc], **kw)

    def set_mtu(self, mtu):
        self._env["INTERNAL_IP4_MTU"] = str(mtu)

    def set_ips(self, addr, gw):
        VNABase.set_ips(self, addr, gw)
        self._env["INTERNAL_IP4_ADDRESS"] = addr
        self._env["F"] = gw

    def _set_dns(self, ips, domains):
        self._env["INTERNAL_IP4_DNS"] = " ".join(ips)
        if domains:
            self._env["CISCO_DEF_DOMAIN"] = " ".join(domains)

    def set_routes(self, routes):
        idx = 0
        for itm in routes:

            ranges = gen_ranges(utils.ipstr2int(itm[0]), utils.ipstr2int(itm[1]))

            for ip, masklen, mask in ranges:
                pref = "CISCO_SPLIT_INC_{}_".format(idx)
                self._env[pref + "ADDR"] = ip
                self._env[pref + "MASK"] = mask
                self._env[pref + "MASKLEN"] = str(masklen)
                idx += 1

        self._env["CISCO_SPLIT_INC"] = str(idx)

    def down(self):
        if self.is_up:
            self.run_vpnc("disconnect")
            self.dev.close()
            self.dev = None
            self.is_up = False

    def up(self):
        self.down()
        self.run_vpnc("connect")
        if self.dev is None:
            self.dev = TunTapDevicePy(self._name)
        self.is_up = True


class NullDev():

    def __init__(self):
        self.fd = 0

    def read(self):
        return b""

    def write(self, data):
        pass

    def fileno(self):
        return self.fd

    def close(self):
        os.close(self.fd)


class VNANull(VNABase):

    def __init__(self, args):
        super(VNANull, self).__init__(True)
        self.dev = NullDev()

    def _ignore(self, *args):
        pass

    set_ips = set_routes = set_dns = up = down = _ignore


class SocketPairDev():

    def __init__(self):
        self.sp = socket.socketpair(None, socket.SOCK_DGRAM)
        self.proxy_sock().set_inheritable(True)
        self.sock = self.sp[0]
        self.max_len = 65536  # IPv4 max

    def proxy_sock(self):
        return self.sp[1]

    def read(self):
        rcv = self.sock.recv(self.max_len)
        return rcv if rcv else None

    def write(self, data):
        return self.sock.send(data)

    def fileno(self):
        return self.sock.fileno()

    def close(self):
        self.sock.close()


class VNAProxy(VNABase):

    def __init__(self, args):
        super(VNAProxy, self).__init__()
        self._script = args.get("script_tun")
        if not self._script:
            raise RuntimeError("Script name not set")

        self.dev = SocketPairDev()
        self._dns = ""
        self._sc_proc = None
        self.mtu = args.get("mtu", 1500)

    def set_mtu(self, mtu):
        self.mtu = mtu

    def set_routes(self, _):
        pass

    def _set_dns(self, ips, domains):
        self._dns = " ".join(ips)
        self._domain = domains[0] if domains else ""

    def up(self):
        self._sc_proc = None
        proxy_sock = self.dev.proxy_sock()
        vpnfd = proxy_sock.fileno()
        env = {
            "VPNFD": str(vpnfd),
            "INTERNAL_IP4_ADDRESS": self.om_ip(),
            "INTERNAL_IP4_MTU": str(self.mtu)
        }
        if self._dns:
            env["INTERNAL_IP4_DNS"] = self._dns
            if self._domain:
                env["CISCO_DEF_DOMAIN"] = self._domain  # only one domain supported

        DEVNULL = subprocess.DEVNULL
        kw = {"env": env, "start_new_session": True, "pass_fds": (vpnfd,),
              "stdin": DEVNULL, "stdout": DEVNULL, "stderr": subprocess.STDOUT
              }
        self._sc_proc = subprocess.Popen(shlex.split(self._script), **kw)
        proxy_sock.close()
        self.is_up = True

    def down(self):
        if self._sc_proc:
            os.killpg(self._sc_proc.pid, signal.SIGHUP)
        self.dev.close()


def init_vna(args):
    cls_list = [VNAProxy, VNAVPNC, VNANM, VNASD, VNANull]
    if args.get("null"):
        cls_list = [VNANull]
    logger.debug("initializing VNA...")
    for cls in cls_list:
        try:
            logger.debug("trying CLASS={}".format(cls))
            inst = cls(args)
            break
        except:
            pass
    if isinstance(inst, VNANull):
        logger.warning("Initializing null VNA for debugging. Network packet transfer won't be available.")
    return inst
