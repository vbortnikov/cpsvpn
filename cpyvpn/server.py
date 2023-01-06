# coding: utf-8
# Created on 07.05.2021
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import ssl
import copy
import urllib
import struct
import secrets
import logging
import asyncio
import argparse
import posixpath

from datetime import datetime, timedelta
from importlib import resources

from collections import defaultdict
from string import Template
from  io import BytesIO as BIO
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from . import cfg
from . import vna
from . import rsa
from . import snx
from . import auth
from . import utils
from . import trutils

as_bytes = utils.as_bytes

logger = logging.getLogger()

pkg_data = utils._pkg_ + ".data"
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.keylog_filename = os.getenv('SSLKEYLOGFILE')

with resources.path(pkg_data, 'cert.pem') as certpem:
    with resources.path(pkg_data, 'key.pem') as keypem:
            context.load_cert_chain(certpem, keypem)
context.verify_mode = ssl.CERT_NONE
context.set_ciphers("DEFAULT")


class Session:

    def __init__(self, sid, ttl):
        self.sid = sid
        self.cookie = None
        self.exp = datetime.now() + timedelta(seconds=ttl)

    def is_valid(self):
        return self.exp > datetime.now()


class SessionPool:

    def __init__(self, ttl=3600 * 7 * 24):
        self.ttl = ttl
        self._sessions = {}

    def new_session(self):
        sid = secrets.token_hex(16)
        s = Session(sid, self.ttl)
        self._sessions[sid] = s
        return s

    def is_valid(self, sid):
        s = self.get_session(sid)
        return s is not None and s.is_valid()

    def is_valid_cookie(self, c):
        s = self.find_session(c)
        return s and s.is_valid()

    def find_session(self, cookie):
        for s in self._sessions.values():
            if s.cookie == cookie:
                return s

    def get_session(self, sid):
        return self._sessions.get(sid, None)

    def remove_session(self, sid):
        self._sessions.pop(sid, None)


spool = SessionPool()


class ClientPool:

    def __init__(self, ip_range):
        self._clients = {}
        self.ip_low, self.ip_high = ip_range

    def register(self, t, old_ip):
        ret = None
        if old_ip:
            if old_ip not in self._clients:
                ret = old_ip
            else:
                old_ip = 0
        if not old_ip:
            for ret in range(self.ip_low, self.ip_high + 1):
                if ret not in self._clients:
                    break
        if ret is None:
            raise RuntimeError("Failed to allocate IP for client!")
        self._clients[ret] = t
        return ret

    @classmethod
    def get_ips(cls, pkt):
        start = 12
        iplen = 4
        return struct.unpack("!II", pkt[start:start + 2 * iplen])

    def remove(self, ip):
        if ip in self._clients:
            del self._clients[ip]

    def route_packet(self, pkt):
        dst = self.get_ips(pkt)[1]
        prot = self._clients.get(dst, None)
        if prot is not None:
            prot.send_packet(pkt)


class HTTPData:
    endl = b'\r\n'

    hdrend = endl * 2
    hdrend2 = b'\n\n'

    def __init__(self, ver):
        self.ver = ver
        self.data = self.resp_code = b''
        self._headers = defaultdict(list)

    def set_responce_code(self, code):
        self.resp_code = code

    def add_header(self, k, v):
        self._headers[k].append(v)

    def add_data(self, data):
        self.data = data

    def _header_bytes(self):
        ret = b''
        for k in self._headers:
            v = self._headers[k]
            v = v if isinstance(v, (list, tuple)) else [v]
            for e in v:
                ret += as_bytes(k + ": " + str(e)) + self.endl
        return ret

    def to_bytes(self):
        endl = self.endl
        ret = b''
        data = as_bytes(self.data)
        cl = "Content-Length"
        self._headers[cl] = [len(data)]

        cmode = "close"
        if self.ver > 10:
            cmode = "Keep-Alive"
        self._headers["Connection"] = cmode

        ret += self._header_bytes()
        ret += endl + data
        if self.resp_code:
            rc = self.resp_code
            v = self.ver
            hdr = "HTTP/{}.{} {} {}".format(v // 10, v % 10, rc.value, rc.phrase)
            ret = as_bytes(hdr) + endl + ret

        return ret


# HTTPS layer
class BaseHTTPHandler:

    ver = 10

    @classmethod
    def init_http_data(cls):
        return HTTPData(cls.ver)

    def __init__(self, opts):
        self.opts = opts
        self.ip = ""

    def set_server_ip(self, ip):
        self.ip = ip

    def process(self, tr, req):
        self.transport = tr
        m, p = req.get_request()
        mthd = getattr(self, m, None)
        logger.debug("\n{} {}\nhdrs:\n{}\ndata\n{}".format(m, p , req.headers, req.data.decode()))
        if mthd:
            mthd(req)

    def send_response(self, resp):
        rc = resp.resp_code
        logger.debug("{} {} {}".format(rc.value, rc.phrase, resp._header_bytes()))
        self.transport.write(resp.to_bytes())


class STDHTTPHandler(BaseHTTPHandler):

    def do_ccc_ClientHello(self, rd, resp):
        ci = resp.find("connectivity_info")
        gw_ip = rd.find("gw_ip")
        sip = self.ip
        ci["server_ip"] = gw_ip if gw_ip else sip
        rdr = resp.find("ResponseData")
        if resp.find("login_options_data") and not self.opts.mr:
            rdr.pop("login_options_data")
        return resp

    @classmethod
    def _gen_session(cls):
        s = spool.new_session()
        s.cookie = secrets.token_hex(32)
        ak = auth.enc(s.cookie)
        return s, ak

    def do_ccc_UserPass(self, rq, resp):
        u = auth.dec(rq.find("username"))
        p = auth.dec(rq.find("password"))
        opts = self.opts

        s, ak = self._gen_session()

        ou, op = opts.user, opts.pwd
        auth_variants = set(((ou, op), (ou, ""), (ou, op + opts.otp)))

        rd = resp.find("ResponseData")
        if (u, p) in auth_variants:
            rd["active_key"] = ak
            rd["session_id"] = s.sid
        else:
            for k in list(rd.keys()):
                if k == "authn_status":
                    continue
                rd.pop(k)
            rd["is_authenticated"] = "false"
            rd["error_code"] = "101"
            rd["error_message"] = auth.enc("Access denied - User authentication failed")
        return resp

    def do_ccc_CertAuth(self, rq, resp):
        s, ak = self._gen_session()
        rd = resp.find("ResponseData")
        rd["active_key"] = ak
        rd["session_id"] = s.sid
        return resp

    def do_ccc_ClientSettings(self, rq, resp):
        sid = rq.find("RequestHeader").get("session_id", "")
        rd = resp.find("ResponseData")
        rd["session_id"] = sid

        if spool.is_valid(sid):
            sip = self.ip
            rd["gw_internal_ip"] = sip
        else:
            pass
        return resp

    def do_ccc_KeyManagement(self, rq, resp):
        # XXX: proper implementation needed
        rd = resp.find("ResponseData")
        rd["om_addr"] = ""
        rd["om_subnet_mask"] = ""
        return resp

    def do_ccc_Signout(self, rq, resp):
        rh = rq.find("RequestHeader")
        sid = rh.get("session_id", "")
        spool.remove_session(sid)
        return resp

    def POST(self, req):

        def send_br():
            resp = self.init_http_data()
            resp.set_responce_code(HTTPStatus.BAD_REQUEST)
            self.send_response(resp)

        p = req.path
        if "clients" not in p:
            send_br()
            return

        opts = self.opts
        data = req.data.decode()
        if not data:
            send_br()
            return

        logger.debug("request:'{}'".format(data))
        cprr = cfg.CPRR(data)
        rh = cprr.find("RequestHeader")
        rhtype = rh["type"]
        rid = rh["id"]
        sid = rh.get("session_id", "")
        srvresp = cfg.CPRR(copy.deepcopy(opts.rrl.get_ccc_server(rhtype)))
        srvrh = srvresp.find("ResponseHeader")
        srvrh["id"] = rid
        srvrh["session_id"] = sid

        mthd = getattr(self, "do_ccc_" + rhtype, None)
        if mthd:
            ret = mthd(cprr, srvresp).serialize()
            logger.debug("resp: {}".format(ret))
            resp = self.init_http_data()
            resp.set_responce_code(HTTPStatus.OK)
            resp.add_data(ret.encode("utf8"))
            self.send_response(resp)

    def GET(self, _):
        data = '''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
<TITLE> 404 File Not Found </TITLE>
</HEAD>
<BODY>
The URL you requested could not be found on this server.
</BODY>
</HTML>
'''
        resp = self.init_http_data()
        resp.set_responce_code(HTTPStatus.NOT_FOUND)
        resp.add_data(data)
        self.send_response(resp)


class MAHTTPHandler(STDHTTPHandler):

    cookie_tag = "CPCVPN_SESSION_ID"
    auth_sid_tag = "AuthSessionID"
    main_login = "/sslvpn/Login/Login"
    exp = "expires=Mon, 13-Aug-1979 01:00:00 GMT; "
    ver = 11

    def __init__(self, opts):
        super(MAHTTPHandler, self).__init__(opts)
        self.rsadec = rsa.RSADec(opts.mod, opts.d)

    def set_auth_cookie(self, sid, resp):
        exp = self.exp if not sid else ""
        resp.add_header("Set-Cookie", '{}={};  {}path=/; secure; HttpOnly'.format(self.auth_sid_tag, sid, exp))

    def set_sid_cookies(self, sid, resp):
        server_name = self.ip
        obs = secrets.token_hex(16)
        exp = ""
        if not sid:
            server_name = obs = ""
            exp = self.exp

        resp.add_header("Set-Cookie", '{}={}; {}path=/; secure; HttpOnly'.format(self.cookie_tag, sid, exp))
        resp.add_header("Set-Cookie", 'CPCVPN_BASE_HOST={}; {}path=/; secure; HttpOnly'.format(server_name, exp))
        resp.add_header("Set-Cookie", 'CPCVPN_OBSCURE_KEY={}; {}path=/; secure; HttpOnly'.format(obs, exp))

    def send_login(self):

        resp = self.init_http_data()
        resp.set_responce_code(HTTPStatus.MOVED_PERMANENTLY)
        resp.add_header("Location", self.main_login)
        self.send_response(resp)

    @classmethod
    def _process_path(cls, p):
        path = p.split('?', 1)[0]
        path = path.split('#', 1)[0]

        try:
            path = urllib.parse.unquote(path, errors='surrogatepass')
        except UnicodeDecodeError:
            path = urllib.parse.unquote(path)
        path = posixpath.normpath(path)
        fname = posixpath.split(path)[1]
        return path, fname

    def GET(self, req):
        p = req.path
        _, fname = self._process_path(p)
        if self._do_redir(p):
            return
        sid = None
        if not (self.main_login in p or "." in fname):
            sid = self._get_ma_sid(req)
            if not spool.is_valid(sid):
                self.send_login()
                return

        self._send_file(req, fname, sid)

    @classmethod
    def _get_ma_sid(self, req):
        sid = ""
        # POST variant
        cookies = req.get_header("Cookie")
        if cookies:
            for e in cookies.split(";"):
                if self.cookie_tag in e or self.auth_sid_tag in e:
                    sid = e.split("=")[1].strip()
                    if sid:
                        break
        # GET variant
        if not sid:
            getreqdict = {}
            gpars = req.path.split('?', 1)
            if len(gpars) > 1:
                getreqdict = urllib.parse.parse_qs(gpars[1])
                sid = getreqdict.get("params", [''])[0]
        return sid

    def _do_redir(self, path):
        if not path or "sslvpn" not in path:
            self.send_login()
            return True

    def POST(self, req):
        p = req.path
        path, fname = self._process_path(p)

        if "clients" in path:
            super(MAHTTPHandler, self).POST(req)
            return

        if self._do_redir(path):
            return
        new_location = ""
        resp = self.init_http_data()
        opts = self.opts
        reqdict = urllib.parse.parse_qs(req.data)
        pwd = reqdict.get(b"password", [''])[0]

        sid = self._get_ma_sid(req)
        if sid:
            if not spool.is_valid(sid):
                self.send_login()
                return

        if pwd:
            pwd = self.rsadec.decrypt(pwd)[:-1]
        if fname == "Login":
            user = reqdict.get(b"userName", [''])[0]
            selectedRealm = reqdict.get(b"selectedRealm", [''])[0]
            opts_user = opts.user.encode()
            opts_pwd = opts.pwd.encode()

            ou, op = opts_user, opts_pwd
            auth_variants = set(((ou, op), (ou, op + opts.otp.encode())))

            logger.info("user {} pwd {}".format(user, pwd))
            logger.info("auth_variants {}".format(auth_variants))

            if (user, pwd) not in auth_variants:
                self.send_login()
                return

            sess = spool.new_session()

            if selectedRealm == b'ssl_vpn_TwoFactor':
                fname = "MultiChallenge"
                new_location = "/sslvpn/Login/MultiChallenge?params={}".format(sess.sid)
                self.set_auth_cookie(sess.sid, resp)
                sess.exp = datetime.now() + timedelta(seconds=4 * 60)

            else:
                new_location = "/sslvpn/Portal/Main"
                self.set_sid_cookies(sess.sid, resp)

        elif fname == "MultiChallenge":
            tempsess = spool.get_session(sid)
            if not tempsess or not tempsess.is_valid():
                self.send_login()

            opts_mc = str(opts.otp).encode()
            logger.info("otp opts {} inc {}".format(opts_mc, pwd))
            if pwd != opts_mc:
                new_location = "/sslvpn/Login/MultiChallenge?params={}".format(tempsess.sid)
            else:
                spool.remove_session(sid)
                sid = spool.new_session().sid
                new_location = "/sslvpn/Portal/Main"
                self.set_auth_cookie("", resp)
                self.set_sid_cookies(sid, resp)
        elif fname == "SignOut":
            if "SignOut" in  req.get_header("Referer"):
                self.set_sid_cookies("", resp)

        if new_location:
            resp.set_responce_code(HTTPStatus.MOVED_PERMANENTLY)
            resp.add_header("Location", new_location)
            self.send_response(resp)
            return
        self._send_file(req, fname, sid)

    def _send_file(self, req, fname, sid):
        resp = self.init_http_data()
        opts = self.opts
        ref = req.get_header("Referer")
        if fname == "SignOut" and (ref and "SignOut" in ref):
            fname = "SignOutFin"
            spool.remove_session(sid)

        try:
            if opts.mr and fname == "Login":
                fname += "MR"
            with resources.open_text(pkg_data + ".ma", fname) as f:
                data = f.read()

                sz = len(data)
                logger.debug("will send {} ({} bytes)".format(fname, sz))
                resp.set_responce_code(HTTPStatus.OK)

                cookie = ""
                sess = spool.get_session(sid)
                if sess is not None:
                    cookie = sess.cookie = secrets.token_hex(32)

                data = Template(data)
                data = data.safe_substitute({"user":opts.user,
                                             "cck":cookie,
                   "host":self.opts.hostname, "port":self.opts.port,
                   "srv_cn":self.ip,
                   "mod":"{:x}".format(opts.mod),
                   "exp":"{:x}".format(opts.exp)
                })
                resp.add_data(data)

                self.send_response(resp)
        except:
            resp.set_responce_code(HTTPStatus.NOT_FOUND)
            self.send_response(resp)
            return


# SSL layer - process or redirect to HTTP
class SNXHandler(snx.SNX):

    def __init__(self, opts):
        super(SNXHandler, self).__init__(opts.vna)
        self.opts = opts
        self.tunip = None

    def ev_drop(self):
        self.disconnect(None)

    def ev_hr(self):
        opts = self.opts
        repl = copy.deepcopy(opts.rrl.get_slim("hello_reply"))
        hr = repl["hello_reply"]
        hr["OM"]["ipaddr"] = self.tunip
        hr ["range"] = hr ["range"][::2]
        data = cfg.CPRR(repl).serialize()
        self.send_cmd(data)

    def keepalive(self, _):
        logger.debug("KA")
        self.send_cmd(self.KA_msg)
        self.KA_cnt += 1
        if self.opts.ie and  self.KA_cnt >= self.opts.ieka:
            logger.debug("Injecting event {}".format(self.opts.ie))
            getattr(self, "ev_" + self.opts.ie)()

    def disconnect(self, _):
        sess = spool.get_session(self.sid)
        sess.cookie = None
        self.transport.close()
        peer = self.transport.transport.get_extra_info('peername')[0]
        logger.debug("SLIM disconnect. OM IP {}, IP {}, sid {}".format(self.tunip, peer, self.sid))

    def client_hello(self, rr):
        self.KA_cnt = 0
        old_ip = None
        cv = rr.find("client_version")
        pv = rr.find("protocol_version")
        cookie = rr.find("cookie")
        sess = spool.find_session(cookie)
        self.sid = None
        if not (sess and sess.is_valid() and sess.cookie == cookie):
            repl = copy.deepcopy(self.opts.rrl.get_slim("disconnect"))
            dr = repl["disconnect"]
            dr["code"] = "201"
            dr["message"] = "Authentication failed"
            data = cfg.CPRR(repl).serialize()
        else:
            self.sid = sess.sid

            self.tunip = retip = utils.ipint2str(self.opts.cpool.register(self, old_ip))

            repl = copy.deepcopy(self.opts.rrl.get_slim("hello_reply"))
            hr = repl["hello_reply"]
            hr["version"] = cv
            hr["protocol_version"] = pv
            if int(pv) == 2:
                hr["protocol_minor_version"] = 0
                hr["allow_VPN_routing_from_SR"] = "false"
                pc = rr.find("policy_components")
                if pc:
                    comp = pc.get("component")
                    if comp == "range":
                        cs = self.opts.rrl.get_ccc_server("ClientSettings")
                        rv = cs["CCCserverResponse"]["ResponseData"]["updated_policies"]["gateway_policy_version"]
                        hr["policy_versions"] = {"range":rv}
                        del hr["range"]

            hr["OM"]["ipaddr"] = retip
            data = cfg.CPRR(repl).serialize()
        self.send_cmd(data)
        logger.debug(data)
        if self.sid is None:
            self.transport.close()

    def on_connection_lost(self, e):
        if self.tunip:
            self.opts.cpool.remove(utils.ipstr2int(self.tunip))


# Small wrapper/helper
class HTTPRH(BaseHTTPRequestHandler):

    def get_header(self, k):
        return self.headers.get(k)

    def get_request(self):
        return self.command, self.path

    class wfile:

        def flush(self):
            pass

    def do_POST(self):
        pass

    def do_GET(self):
        pass

    def __init__(self, data):
        self.rfile = BIO(data)
        self.wfile = self.wfile()


class TLSHandler(trutils.TransportBase, asyncio.Protocol):

    def __init__(self, http_handler, opts):
        super(TLSHandler, self).__init__()
        self._snx = SNXHandler(opts)
        self._http_handler = http_handler

    def connection_made(self, t):
        super(TLSHandler, self).connection_made(t)
        self._snx.connection_made(t)
        self._hdr = b''
        self._body = b''
        self._req = None
        self._snxmode = False

    def data_received(self, data):
        has_hdr = len(self._hdr) != 0
        has_body = self._req is not None
        has_text = data[0] != 0 and not self._snxmode
        init = False
        # Either GET/POST or SNX proto
        if not (has_hdr or has_body) and has_text:
            init = True
            self._hdr = data

        if self._hdr:
            if not init:
                self._hdr += data
            hdrend = HTTPData.hdrend
            pos = self._hdr.find(HTTPData.hdrend)
            if  pos < 0:
                pos = self._hdr.find(HTTPData.hdrend2)
                hdrend = HTTPData.hdrend2
                if  pos < 0:
                    return
            self._req = rh = HTTPRH(self._hdr)
            rh.handle_one_request()

            self._body = self._hdr[pos + len(hdrend):]
            self._hdr = b''

        if self._req:
            datalen = int(self._req.headers.get("Content-Length", 0))
            if len(self._body) < datalen:
                if not init:
                    self._body += data
                if len(self._body) < datalen:
                    return
            self._req.data = self._body

            self._http_handler.process(self.transport, self._req)
            self._body = self._hdr = b''
            self._req = None

            return

        self._snx.data_received(data)
        self._snxmode = True

    def send_packet(self, pkt):
        self._snx.send_packet(pkt)

    def on_connection_lost(self, e):
        self._snx.on_connection_lost(e)


class TlsMemTransport:

    def __init__(self, transport, handler):
        self.transport = transport
        self.handler = handler
        self.tls_in_buff = ssl.MemoryBIO()
        self.tls_out_buff = ssl.MemoryBIO()
        self.tls_obj = context.wrap_bio(self.tls_in_buff, self.tls_out_buff, server_side=True)
        self._do_hs = True

    def write(self, data):
        self.tls_obj.write(data)
        while 1:
            tlsdata = self.tls_out_buff.read()
            if not tlsdata:
                break
            self.transport.write(tlsdata)

    def process_incoming(self, data):

        self.tls_in_buff.write(data)
        if self._do_hs:
            try:
                self.tls_obj.do_handshake()
                self._do_hs = False
                self.handler.connection_made(self)
                self.client_cert = self.tls_obj.getpeercert()
                logger.debug('client_cert: {}'.format(self.client_cert))
            except ssl.SSLWantReadError:
                pass

            server_req = self.tls_out_buff.read()
            self.transport.write(server_req)

        else:

            while True:
                try:
                    data = self.tls_obj.read()
                    if not data:
                        break
                    self.handler.data_received(data)
                except ssl.SSLWantReadError:
                    break

    def close(self):
        self.transport.close()


# RAW TCP layer
class TCPHandler(trutils.FramedTransportMixin, asyncio.Protocol):

    def __init__(self, opts, http_handler_factory):
        super(TCPHandler, self).__init__()
        self.opts = opts
        self._handler_factory = http_handler_factory

    def connection_made(self, t):
        self.is_tls = True
        super(TCPHandler, self).connection_made(t)

        handler = self._handler_factory(self.opts)
        ip = self.transport.get_extra_info('sockname')[0]
        peerip = self.transport.get_extra_info('peername')[0]
        handler.set_server_ip(ip)
        logger.debug("client ip {}, server ip {}".format(peerip, ip))
        self.tls_mt = TlsMemTransport(t, TLSHandler(handler, self.opts))

    def send_esp(self, data):
        pass

    def send_packet(self, data):
        if self.is_tls:
            self.tls_mt.handler. send_packet(data)
        else:
            self.send_esp(data)

    def process_incoming(self, data, dtype):
        if dtype == self.TLS:
            self.tls_mt.process_incoming(data)
        else:
            logger.debug("{} {}".format(data, dtype))
            en_esp_tcpt = struct.pack("!III", 1, 4, 1)  # Enable tcpt-esp transport
            en_kmp_tcpt = struct.pack("!III", 1, 2, 1)  # Enable kmp transport
            if dtype == self.CMD:
                # IPSEC enable
                if data in [en_kmp_tcpt, en_esp_tcpt]:
                    self.is_tls = False
                    resp_ok = struct.pack("!II", 0, 1)
                    self.send_cmd(resp_ok)
            elif dtype == self.ESPT:
                pass

    def on_connection_lost(self, e):
        self.tls_mt.handler.on_connection_lost(e)


def main():
    global context
    rrl = cfg.RRLib(resources.open_text(pkg_data, "rr.js"))
    hr = rrl.get_slim("hello_reply")
    iprng = hr["hello_reply"]["range"][0]
    parser = argparse.ArgumentParser(description="CheckPoint VPN test server.")
    parser.add_argument("-u", "--user", type=str, default="t", help="Test user name. Default  %(default)s.")
    parser.add_argument("-p", "--pwd", type=str, default="t", help="Test user password. Default  %(default)s.")
    parser.add_argument("--ma", action='store_true', default=False, help="Emulate mobile access portal. Default %(default)s.")
    parser.add_argument("--cc", action='store_true', default=False, help="Allow login with client certificate. Default %(default)s.")
    parser.add_argument("--mr", action='store_true', default=False, help="Enable multiple realm mode.")
    parser.add_argument("--otp", type=str, default="1234", help="Pin or Multi Challenge code. Default  is %(default)s if not given. Set to empty string to disable 2FA mode.")
    parser.add_argument("--port", type=int, default=4433, help="Listen port. Default  %(default)s.")
    parser.add_argument("--addr", type=str, default="0.0.0.0", help="Listen address. Default  %(default)s.")
    parser.add_argument("--hostname", type=str, default="localhost", help="Address for external connections and SSL. Default  %(default)s.")
    parser.add_argument("--dv", action='store_true', default=False, help="Use dummy VNA.")
    parser.add_argument("--ip_range", type=str, nargs='+', default=[iprng["from"], iprng["to"]], help="Dummy socket for emulated VNA debug.")
    parser.add_argument("--ie", type=str, help=argparse.SUPPRESS)
    parser.add_argument("--ieka", type=int, help=argparse.SUPPRESS)

    utils.add_common_args(parser)
    options = parser.parse_args()
    utils.setup_loglevel(options)

    logger.debug(options)
    if not (options.pwd and options.user):
        raise RuntimeError("Username/Pwd must be set!")

    if len(options.ip_range) != 2:
        raise RuntimeError("Bad ip_range!")

    options.rrl = rrl
    if options.ma:
        with resources.open_text(pkg_data, "rsa.keys") as f:
            options.mod = int(next(f))
            options.exp = int(next(f))
            options.d = int(next(f))
    if options.cc:
        with resources.path(pkg_data, 'cl_cert.pem') as clcertpem:
            context.load_verify_locations(cafile=clcertpem)
            context.verify_mode = ssl.CERT_REQUIRED

    hander = MAHTTPHandler if options.ma else STDHTTPHandler
    kw = {"interface":"snxtunsrv"}
    if options.dv:
        kw["null"] = 1
    with vna.init_vna(kw) as  vna_obj:
        options.vna = vna_obj
        ip_min, ip_max = options.ip_range
        ip_min_int, ip_max_int = [utils.ipstr2int(e) for e in options.ip_range]
        ip_srv = utils.ipint2str(ip_min_int + 1)

        options.cpool = cpool = ClientPool((ip_min_int + 3, ip_max_int))
        vna_obj.set_ips(ip_srv, ip_srv)
        vna_obj.set_routes([(ip_min, ip_max)])
        vna_obj.up()

        vnafd = vna_obj.tundev().fileno()

        def read_vna():
            data = vna_obj.tundev().read()
            cpool.route_packet(data)

        try:
            loop = asyncio.get_event_loop()
            coro = loop.create_server(lambda: TCPHandler(options, hander), options.addr, options.port)
            server = loop.run_until_complete(coro)
            if vnafd:
                loop.add_reader(vnafd, read_vna)
            utils.print_close_info()
            loop.run_forever()
        except KeyboardInterrupt:
            logger.debug("KeyboardInterrupt")
        loop.remove_reader(vnafd)

    logger.debug("Closing everything")
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == "__main__":
    main()
