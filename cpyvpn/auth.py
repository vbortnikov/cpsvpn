# -*- coding: utf-8 -*-
# Created on 02.12.2020
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import re
import json
import urllib
import secrets
import datetime
import logging

from . import utils, ssl_ctx
from .cfg import CPRR

logger = logging.getLogger()

# login/pwd handling
table = [

    0x2D, 0x4F , 0x44 , 0x49 , 0x46 , 0x49 , 0x45 , 0x44  , 0x26 , 0x57 , 0x30 , 0x52 , 0x4F , 0x50 , 0x45 , 0x52
    , 0x54 , 0x59 , 0x33 , 0x48 , 0x45 , 0x45 , 0x54 , 0x37  , 0x49 , 0x54 , 0x48 , 0x2F , 0x2B , 0x34 , 0x48 , 0x45
    , 0x33 , 0x48 , 0x45 , 0x45 , 0x54 , 0x29 , 0x24 , 0x33  , 0x3F , 0x2C , 0x24 , 0x21 , 0x30 , 0x3F , 0x21 , 0x35
    , 0x3F , 0x30 , 0x32 , 0x2F , 0x30 , 0x25 , 0x32 , 0x34  , 0x29 , 0x25 , 0x33 , 0x2E , 0x35 , 0x2C , 0x2C , 0x10
    , 0x26 , 0x37 , 0x3F , 0x37 , 0x30 , 0x3F , 0x2F , 0x22  , 0x2A , 0x25 , 0x23 , 0x34 , 0x33 , 0x00 , 0x00 , 0x00
    , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00  , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00
    ]


def enc_dec_ichr(i, ordc):

    if ordc == 0xff:
        ordc = 0

    prod = (i * 0x3531DEC1)
    phigh = prod >> (32 + 4)
    ofs2 = phigh

    ofs = ofs2 + ofs2 * 8
    ofs = ofs2 + ofs * 2
    ofs = ofs2 + ofs * 4
    ofs = ofs2 + (ofs2 + (ofs2 + ofs2 * 8) * 2) * 4

    idx = i - ofs

    ret = ((table[idx] ^ ordc))
    if ret == 0:
        ret = 0xff
    return ret


def enc(data):
    data = utils.as_text(data)
    ret = []
    for i, e in enumerate(data):
        orde = ord(e)
        ret.append(enc_dec_ichr(i, orde))
    return ''.join(("{:02x}".format(n) for n in reversed(ret)))


def dec(data, unscramble=True):
    data = utils.as_text(data)
    sbytes = bytes.fromhex(data)

    rev = reversed(sbytes)
    if unscramble:
        ret = []
        for i, e in enumerate(rev):
            ret.append(enc_dec_ichr(i, e))
        return ''.join(("{:c}".format(n) for n in ret))
    else:
        return bytes(rev)


class AuthHelper(object):
    '''
    Perform auth actions to obtain cookie in regular and Mobile Access (extender) mode.
    '''

    def __init__(self, ct, realm={}, login=None, pwd=None, cert_path="/clients/cert/", url=None, ma_cookies=None, ui=None):  # host,port,login, pwd,
        self.ct = ct
        self.realm = realm
        self._logopt = realm.get("id", "")
        self.login = login
        self.pwd = pwd
        self.cert_path = cert_path
        self.url = url
        self.ma_cookies = ma_cookies
        self.ui = ui
        self.sid = self.auth_exp = None

    def cert_login(self):
        body = CPRR({"CCCclientRequest":
              {"RequestHeader":{
                  "id":1,
                  "type":"CertAuth",
                  "session_id":""
                  },
              "RequestData":{
                  "client_type":self.ct,
                  "selectedLoginOption":self._logopt
                  }
              }
              }).serialize()[:-1]
        logger.info("Cert. login")
        return self._extract_ac(self.url + self.cert_path, body)

    def do_login(self):

        logger.info("Standard login")
        body = CPRR({"CCCclientRequest":
              {"RequestHeader":{
                  "id":2,
                  "type":"UserPass",
                  "session_id":""
                  },
              "RequestData":{
                  "client_type":self.ct,
                  "username":enc(self.login),
                  "password":enc(self.pwd),
                  "selectedLoginOption":self._logopt
                  }
              }
              }).serialize()[:-1]

        return self._extract_ac(self.url + "/clients/", body)

    def _extract_ac(self, url, body):

        rd = utils.do_ccc_request(url, data=body).find("ResponseData")

        if rd.get("authn_status") == "continue":

            prompt = dec(rd.get("prompt"))
            quser_input = self.ui.ask_str(prompt)
            user_input = self.ui.wait_input([quser_input])[0]

            sid = rd.get("session_id")
            mcbody = CPRR(
                {"CCCclientRequest":
                  {"RequestHeader":{
                      "id":1,
                      "type":"MultiChallange",
                      "session_id":""
                      },
                  "RequestData":{
                      "client_type":"TRAC",  # Maybe SYMBIAN
                      "auth_session_id":sid,
                      "user_input":enc(user_input)
                      }
                }}).serialize()[:-1]
            return self._extract_ac(url, mcbody)

        active_key = rd.get("active_key", "")
        auth_ok = rd.get("is_authenticated", "") == "true"
        if rd.get("authn_status", "") != "done" or  (not auth_ok) or (not active_key):
            if not auth_ok:
                msgenc = rd.get("error_message", "")
                code = rd.get("error_code", "")
                msg = dec(msgenc)
                if not msg:
                    msg = rd.get("error_msg", "")

            raise Exception("Authentication error: {} (code={})".format(msg, code))
        self.sid = rd.get("session_id")
        self.auth_exp = datetime.datetime.now() + datetime.timedelta(seconds=int(rd.get("active_key_timeout")))
        return dec(active_key)

    def get_extender_data(self):

        ret = utils.do_https_request(self.url, headers={"Cookie":self.ma_cookies})
        pos = ret.find("Extender.user_name")
        info = ""
        if pos >= 0:
            pos2 = ret.find("}", pos)
        if pos >= 0 and pos2 >= 0:
            info = ret[pos:pos2]

        # from snxconnect
        evars = {}
        for stmt in info.split (';'):
            try:
                lhs, rhs = stmt.split ('=')
            except ValueError:
                break
            try:
                lhs = lhs.split ('.', 1)[1].strip ()
            except IndexError:
                continue
            rhs = rhs.strip ().strip ('"')
            evars [lhs] = rhs  # .encode ('utf-8')
        cookie = evars.get("password")
        if not cookie:
            raise Exception("Bad extender page! Check cookies or login again.")
        hostname = evars ["host_name"]
        port = int(evars ["port"])
        info = ""

        m = re.search("snxAppArrJson[^=]*=[^']*'([^']+)';", ret)

        app_arr = None
        if m:
            app_arr = json.loads(m.group(1))
        elif "isSnxBookmarksReady" in ret:
            p = urllib.parse.urlparse(self.url)
            url = p.scheme + "://" + p.netloc + "/SNX/GetSnxBookmarks"

            retbm = utils.do_https_request(url, headers={"Cookie":self.ma_cookies})
            app_arr = json.loads(retbm)['SnxAppsArray']

        if app_arr:
            l = ["title|path|params"]
            for e in app_arr:
                l.append("|".join((e["title"], e["path"], e["params"])))
            info = "\n".join(l)
            logger.info("Available applications\n" + info)

        return (hostname, port, cookie, info)

    def signout(self, pv):
        if self.sid is not None and pv >= 100:
            body = CPRR({"CCCclientRequest":
              {"RequestHeader":{
                  "id":4,
                  "type":"Signout",
                  "session_id":self.sid,
                  "protocol_version":pv
                  },
              "RequestData":{}
              }
              }).serialize()[:-1]
            try:
                utils.do_ccc_request(self.url + "/clients/", body, rc_check=False)
            except utils.CCCBadRetCode:
                logger.info("Signout error. It is expected for R81 gateways.")


class SNXAuth:
    CCCClientHello = CPRR({"CCCclientRequest":{
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
        }).serialize()

    class Opts:
        pass

    def __init__(self, opts, ui):
        self.opts = opts
        self.ui = ui
        self.opts.url = self.opts.server
        self.auth_obj = None
        self.use_ma = False

        logger.info("GW url(host) is: {}".format(self.opts.url))
        p = utils.parseurl(self.opts.url)
        host, port = p.host, p.port
        ssl_ctx.check_ssl_mode(host, port, opts.nocert)

        self.gw_info = gwi = utils.get_gw_info("{}:{}".format(p.host, p.port))
        self.cert_url, self.cookie_name = gwi.cert_url, gwi.cookie_name

    def init(self):

        def ma_login():
            from . import ma
            opts = self.Opts()
            opts.host = self.opts.url
            opts.username = self.opts.user
            opts.ua = self.opts.ua
            opts.filepref = None
            opts.filename = self.opts.path
            opts.realm = self.opts.realm  # ssl_vpn
            opts.cookies = self.opts.cookies
            opts.login_type = ""
            opts.vpid_prefix = ""
            self.mar = mar = ma.MARequester(opts, self.ui)

            mar.ma_login()
            url = mar.extender
            reprcookies = self.opts.cookies
            if not reprcookies:
                cookies = []
                for c in mar.jar:
                    nm = c.name
                    if self.cookie_name in  nm:
                        cookies.append(nm + "=" + c.value)
                reprcookies = "; ".join(cookies)
            return url, reprcookies

        self.tun = None
        self.again = False
        realm = ""
        p = utils.parseurl(self.opts.url)

        mode = self.opts.mode[0]
        self.use_ma = use_ma = mode == 'm'
        self.cert_login = mode == 'c'

        if use_ma:
            url, cookies = ma_login()
            self.auth_obj = AuthHelper("TRAC", url=url, ma_cookies=cookies)
        else:
            header = ""
            user_prompt = "User"
            pwd_prompt = "Password"
            realm = self.opts.realm
            realms = self.gw_info.realms
            login_realm = {}
            nr = len(realms)
            if nr == 1:
                login_realm = realms[0]
                realm = login_realm["id"]

            elif realm:
                try:
                    realm = realms[int(realm) - 1].get("id")
                except ValueError:
                    found_realm = None
                    for r in realms:
                        rid = r.get("id")
                        if rid == realm or r.get("display_name") == realm:
                            found_realm = rid
                            login_realm = r
                            break
                    if found_realm is None:
                        raise RuntimeError("Can't find realm with id or display_name equal to '{}'".format(realm))
                    realm = found_realm

            if not realm and nr > 0:
                if nr > 1:
                    sel = [(i, r["display_name"]) for i, r in enumerate(realms)]
                    qv = self.ui.ask_sel("Select login realm (authentication method):", sel)
                    idx = self.ui.wait_input([qv])[0]
                else:
                    idx = 0
                login_realm = realms[idx]

            if login_realm:
                factor0 = login_realm.get("factors", {}).get("0", {})
                factor_type = factor0.get("factor_type")
                if factor_type == "certificate":
                    self.cert_login = True
                elif factor_type == "securid":
                    ct = factor0.get("securid_card_type")
                    if ct in ["software_token", "any", "pinpad"]:
                        mode = "p"
                    elif ct == "keyfob":
                        mode = "k"

                elif factor_type in [ "password", "username_only"]:
                    mode = "l" if factor_type == "password" else "u"
                    labs = factor0.get("custom_display_labels", {})
                    header = labs.get("header", header)
                    user_prompt = labs.get("username", user_prompt)
                    pwd_prompt = labs.get("password", pwd_prompt)

            if self.cert_login:
                login = pwd = None
            else:
                if mode not in "lpkhu":
                    raise RuntimeError("Can't determine first authentication factor type, please use -m option to select one.")
                self.ui.print_header(header)
                qlogin = qpwd = qpwd2 = None
                if not self.opts.user:
                    qlogin = self.ui.ask_str("Challenge" if mode == "h" else user_prompt)
                else:
                    login = self.opts.user

                optpwd = getattr(self.opts, "pwd", None)
                if optpwd:
                    pwd = optpwd
                else:
                    if mode == "l":
                        qpwd = self.ui.ask_pwd(pwd_prompt)
                    elif mode == "p":
                        qpwd = self.ui.ask_pwd("Passcode")
                    elif mode == "k":
                        qpwd = self.ui.ask_pwd("PIN")
                        qpwd2 = self.ui.ask_pwd("Tokencode")
                    elif mode in ["h", "u"]:  # TODO: check username_only on Capsule!
                        pwd = ""
                    else:
                        raise Exception("Bad mode!")

                vals = self.ui.wait_input([v for v in [qlogin, qpwd, qpwd2] if v is not None])
                if qlogin is not None:
                    login = vals.pop(0)
                if qpwd is not None:
                    pwd = vals.pop(0)
                if qpwd2 is not None:
                    pwd += vals.pop(0)

            url = self.opts.url + "/clients/" if not self.cert_login else self.cert_url
            self.auth_obj = AuthHelper(self.opts.ct, realm=login_realm, login=login, pwd=pwd, cert_path=self.cert_url, url=self.opts.url, ui=self.ui)

        self.host, self.port = (p.hostname, p.port)
        if not self.use_ma:
            self.cookie = self.auth_obj.cert_login() if self.cert_login else self.auth_obj.do_login()

    def get_session_data(self):

        class Ret:
            pass

        ret = Ret()
        if not self.use_ma:
            ret.host, ret.port, ret.cookie = self.host, self.port, self.cookie
        else:
            ret.host, ret.port, ret.cookie, ret.info = self.auth_obj.get_extender_data()
        return ret

    def get_km_data(self, old_ip=None):
        flag, ip = ("true", old_ip) if old_ip else ("false", "0.0.0.0")
        ipint = hex(utils.ipstr2int(ip))
        url = self.opts.url + "/clients/"
        spi = "0x" + secrets.token_hex(4)
        body = '''(CCCclientRequest
    :RequestHeader (
        :id (4)
        :session_id ({})
        :type (KeyManagement)
        :protocol_version (100)
    )
    :RequestData (
        :SPI ({})
        :rekey ({})
        :req_om_addr ({})
    )
)
'''.format(self.auth_obj.sid, spi, flag, ipint)
        return utils.do_ccc_request(url, data=body)

    def signout(self):
        if self.use_ma:
            if self.opts.force_logout or not self.opts.cookies:
                self.mar.signout()
        elif self.auth_obj:
            self.auth_obj.signout(self.gw_info.pv)

    # Small helper to use with closing context manager
    def close(self):
        self.signout()
