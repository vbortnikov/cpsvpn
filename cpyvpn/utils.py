# coding: utf-8
# Created on 02.12.2020
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import re
import os
import os.path as op
import struct
import signal
import socket
import logging

from urllib.parse import urlparse
from urllib.request import build_opener, HTTPSHandler, HTTPCookieProcessor, Request
from http.cookiejar import LWPCookieJar
from http.client import IncompleteRead

from .cfg import CPRR

logger = logging.getLogger()
_pkg_ = op.basename(op.dirname(__file__))

try:
    from . import __version__
    version = __version__.version
except ImportError:
    version = "devel"


def ipstr2int(sip):
    return struct.unpack("!I", socket.inet_aton(sip))[0]


def ipint2str(iip):
    return socket.inet_ntoa(struct.pack("!I", iip))


def as_text(sdata):
    if isinstance(sdata, bytes):
        return sdata.decode()
    return sdata


def as_bytes(sdata):
    if isinstance(sdata, bytes):
        return sdata
    return sdata.encode()


class ParseRes:

    def __init__(self, host, port, path):
        self.host = host
        self.hostname = host
        self.port = port if port else 443
        self.path = path


def add_slash(s):
    pref = "//"
    if ":" + pref not in s:
        s = pref + s
    return s


# Tuny helper for url handling stuff
def parseurl(s):
    p = urlparse(add_slash(s))
    return ParseRes(p.hostname, p.port, p.path)


# Helper to reuse in MA case, when cookies are needed
def make_handlers(with_cookies=False):
    from . import ssl_ctx
    ret = [HTTPSHandler(context=ssl_ctx.get_ssl_context())]
    if with_cookies:
        j = LWPCookieJar ()
        ret.append(HTTPCookieProcessor (j))
    return ret


def do_https_request(url, data=None, headers={}, with_cookies=False, rawval=False, filter_data=False):
    if not url.startswith("https") and not url.startswith("http"):
        url = "https://" + url

    opener = build_opener (*make_handlers(with_cookies))

    logger.debug("Sending request to {}".format(url))
    if headers:
        logger.debug("Request headers {}".format(headers))

    log_data = data
    if filter_data:
        log_data = re.sub(r"(username|password) \([^\)]+\)", r"\1 (X)", data)

    logger.debug("Request data {}".format(log_data))
    if data:
        data = data.encode ('ascii')
    rq = Request (url, data, headers=headers)
    f = opener.open (rq)
    try:
        rdata = f.read ()
    except IncompleteRead as e:
        rdata = e.partial

    ret = rdata if rawval else rdata.decode("utf_8_sig")
    logger.debug("Reply data {}".format(ret))
    return ret


class CCCException(Exception):
    pass


class CCCNoResponseHeader(CCCException):

    def __init__(self):
        super().__init__("No ResponseHeader!")


class CCCBadRetCode(CCCException):

    def __init__(self, code):
        self.code = code
        super().__init__("Bad return_code: {}!".format(code))


class CCCNoResponseData(CCCException):

    def __init__(self):
        super().__init__("No ResponseData!")


def do_ccc_request(url, data=None, headers={}, with_cookies=False, rawval=False, rc_check=True):
    # TODO: check we need all flags??
    rrdata = do_https_request(url, data=data, headers=headers, with_cookies=with_cookies, rawval=rawval, filter_data=True)
    ret = CPRR(rrdata)
    rh = ret.find("ResponseHeader")
    if not rh:
        raise CCCNoResponseHeader()
    rc = int(rh.get("return_code", -1))
    if rc_check and  rc != 600:
        raise CCCBadRetCode(rc)

    rd = ret.find("ResponseData")
    if rd is None:
        raise CCCNoResponseData()
    return ret


def get_ranges(url, sid):
    body = '''(CCCclientRequest
    :RequestHeader (
        :id (3)
        :session_id ({})
        :type (ClientSettings)
        :protocol_version (100)
    )
    :RequestData (ClientSettings
        :requested_policies_and_current_versions (
            :range ()
            :nemo_client_1 ()
        )
    )
)
'''.format(sid)
    ret = do_ccc_request(url + "/clients/", data=body)
    rd = ret.find("ResponseData")
    range_list = rd.get("updated_policies", {}).get("range", {}).get("settings", [])
    return range_list


def process_ranges(range_list, gw_ip):
    gw_ipint = ipstr2int(gw_ip)
    route_list = []

    for itm in range_list:
        ipfrm = itm ["from"]
        ipto = itm ["to"]
        ipf = ipstr2int(ipfrm)
        ipt = ipstr2int(ipto)
        if ipf <= gw_ipint <= ipt:
            if ipf < gw_ipint:
                route_list.append((ipfrm, ipint2str(gw_ipint - 1)))
            if ipt > gw_ipint:
                route_list.append((ipint2str(gw_ipint + 1), ipto))
            continue
        route_list.append((ipfrm, ipto))
    return route_list


# Basic GW info retrieval
def get_gw_info(url):

    class retdata:
        pass

    req = {"CCCclientRequest":{
        "RequestHeader":{
            "id":0,
            "type":"ClientHello",
            },
        "RequestData":{
            "client_info": {
                "client_type":"TRAC",
                "client_version":1
                }
            }
        }
    }
    ret = retdata()

    ret.cert_url = "/clients/cert/"
    ret.cookie_name = "CPCVPN_SESSION_ID"
    reqdata = CPRR(req).serialize()

    rd = do_ccc_request(url + "/clients", data=reqdata).find("ResponseData")

    ret.pv = int(rd.get("protocol_version", {}).get("protocol_version", 0))

    ci = rd.get("connectivity_info", None)
    if ci:
        ret.cert_url = ci.get("connect_with_certificate_url", ret.cert_url)
        ret.cookie_name = ci.get("cookie_name", ret.cookie_name)

    realms = rd.get("login_options_data", {}).get("login_options_list", {})
    ret.realms = [realms[k] for k in realms if int(realms[k].get("show_realm", 0)) == 1]
    return ret


def add_common_args(parser):
    parser.add_argument("--loglevel", type=str, default="INFO", help="Log level. CRITICAL, ERROR, WARNING, DEBUG. Default is '%(default)s'.")
    parser.add_argument('-v', '--version', action='version', version='%(prog)s version {}'.format(version))


def add_common_client_args(parser):
    parser.add_argument("-p", "--path", default="sslvpn", type=str, help="Login form path for MA mode. Default is '%(default)s'.")
    parser.add_argument("-u", "--user", default="", type=str, help="Login (user name).")
    parser.add_argument("-r", "--realm", default="", type=str, help="Realm to use during login if multiple realms are available. Use index, id or display_name here")
    parser.add_argument("-c", "--user_cert", help="User certificate file in PEM format.")
    parser.add_argument("-C", "--cookies", help="Use given authentication cookie(s) when connecting using Mobile Access Portal mode.")
    parser.add_argument("--cookies-on-stdin", dest="stdin_cookies", action='store_true', default=False, help="Read cookie from standard input.")
    parser.add_argument("--passwd-on-stdin", dest="stdin_pwd", action='store_true', default=False, help="Read password from standard input.")
    parser.add_argument("--ua", default="Mozilla/5.0 Gecko/20100101 Firefox/78.0", type=str, help="User agent we are pretending to be. Default is '%(default)s'.")
    parser.add_argument("--nocert", action='store_true', default=False, help="Accept any server certificate, e.g. self-signed one.")


def setup_loglevel(options, add=True):
    numeric_level = getattr(logging, options.loglevel.upper(), "INFO")
    logger.setLevel(numeric_level)
    if add:
        lh = logging.StreamHandler(sys.stdout)
        logger.addHandler(lh)
        return lh


def client_setup(options, add_handler=True):
    from . import ssl_ctx

    def ask_cert_pwd():
        q = options.ui.ask_pwd("Certificate password")
        return options.ui.wait_input([q])[0]

    if options.user_cert:
        ctx = ssl_ctx.get_ssl_context()
        ctx.load_cert_chain(options.user_cert, password=ask_cert_pwd)

    p = urlparse(add_slash(options.server))
    if p.scheme or p.path:
        options.server = p.netloc
    if p.path:
        options.path = p.path
        if hasattr(options, "mode"):
            options.mode = 'm'

    if options.stdin_cookies:
        q = options.ui.ask_str("Cookies")
        options.cookies = options.ui.wait_input([q])[0]
    elif options.stdin_pwd:
        q = options.ui.ask_str("Password")
        options.pwd = options.ui.wait_input([q])[0]
    return setup_loglevel(options, add_handler)


def print_close_info():
    logger.info("Press Ctrl-C or send SIGINT signal to stop this process (pid={}).".format(os.getpid()))


__SIGLIST__ = (signal.SIGINT, signal.SIGTERM)

try:
    #posix
    __SIGLIST__ += (signal.SIGQUIT,)
except AttributeError:
    #win
    try:
        __SIGLIST__ += (signal.CTRL_BREAK_EVENT, signal.CTRL_C_EVENT)
    except AttributeError:
        #other
        pass


def init_sighandlers(l, evt):
    for s in __SIGLIST__:
        l.add_signal_handler(s, evt.set)


def remove_sighandlers(l):
    for s in __SIGLIST__:
        l.remove_signal_handler(s)
