# coding: utf-8
# Created on 02.12.2020
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

# MARequester is based on code from snxvpn utility, distributed under 3-Clause BSD License.
# See https://github.com/schlatterbeck/snxvpn and https://github.com/agnis-mateuss/snxvpn for more info.
#
# Original copyright of snxvpn follows:
# Copyright (C) 2017 Dr. Ralf Schlatterbeck Open Source Consulting.
# Reichergasse 131, A-3411 Weidling.
# Web: http://www.runtux.com Email: office@runtux.com
# All rights reserved

import sys
import re
import json
import struct
import logging
import posixpath as pp
from logging.handlers import SocketHandler
from urllib.request import build_opener, Request
from urllib.parse import urlencode
from http.client import IncompleteRead
from html.parser import HTMLParser
from collections import OrderedDict

from .rsa import RSAEnc
from . import utils, ssl_ctx, cui

logger = logging.getLogger()


# Simple html parser with quirks
class CPHTMLParser(HTMLParser):
    # https://developer.mozilla.org/en-US/docs/Glossary/Empty_element
    noclosing = ["area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr"]
    dump = 0

    class Tag:

        def __init__(self, t, a):
            self.t = t
            self.text = ""
            self.attrs = a
            self.st = []

        def __str__(self):
            return "<{} {}>".format(self.t, str(self.attrs))

        def __repr__(self):
            return str(self)

        def add(self, o):
            self.st.append(o)

        def tag(self):
            return self.t

        def subtags(self):
            return self.st

        @classmethod
        def _dofind(cls, tag, p):
            ret = []
            for k in p.subtags():
                ktag = k.tag()
                if ktag == tag:
                    ret.append(k)
                ret.extend(cls._dofind(tag, k))
            return ret

        def find(self, tag):
            return self._dofind(tag, self)

    def __init__(self):
        super(CPHTMLParser, self).__init__()
        self._root = self.Tag("/", None)
        self._stack = [self._root]

    def handle_startendtag(self, tag, attrs):
        ne = len(self._stack) + 1
        ws = " "*ne
        top = self._stack[-1]
        if self.dump:logger.debug("{} startendtag {}: <{}> (top: {}) {}".format(ws, ne, tag, top, attrs))

        if tag not in self.noclosing:
            self._stack.pop()

    def handle_starttag(self, tag, attrs):
        ne = len(self._stack) + 1
        ws = " "*ne

        top = self._stack[-1]
        if self.dump:logger.debug("{} starttag {}: <{}> (top: {}) {}".format(ws, ne, tag, top, attrs))
        e = self.Tag(tag, OrderedDict(attrs))
        top.add(e)
        if tag not in self.noclosing:
            self._stack.append(e)

    def handle_data(self, data):
        ne = len(self._stack)
        ws = " "*ne
        d = data[:20].strip()
        if self.dump:logger.debug("{} data {}: {}".format(ws, ne, d + "..." if d else ""))
        if self._stack:
            self._stack[-1].text += data

    def handle_endtag(self, tag):
        ne = len(self._stack)
        ws = " "*ne
        if self.dump:logger.debug("{} endtag {}: </{}> (top: {})".format(ws, ne, tag, self._stack[-1]))
        if tag in self.noclosing:
            return
        # End tags may be ommited, or there may be typos, and extras so check
        top = self._stack[-1]
        if top.t != tag:
            # Pop empty element
            if not top.st and not top.text.strip():
                self._stack.pop()
            # Check again if closing match
            top = self._stack[-1]
            if top.t != tag:
                if len(self._stack) > 2:
                    # Tag ommition for the last
                    if self._stack[-2].t == tag:
                        self._stack.pop()
                    else:
                        # Stranded one - ignore
                        return
        toptag = self._stack[-1].t
        if  toptag != tag:
            raise SyntaxError("Closing tag mismatch! endtag= {} top tag={}".format(tag, toptag))
        if tag not in self.noclosing:
            self._stack.pop()
            if self.dump:logger.debug("{} stack.pop".format(ws))

    def unknown_decl(self, data):
        ne = len(self._stack)
        if self.dump:logger.debug("unknown_decl {}: {}".format(ne, data))

    def find(self, tag):
        return self._root.find(tag)


class MARequester:
    zero_tail = b'\x00'

    def __init__(self, args, ui):
        self.args = args
        self.ui = ui
        self.modulus = self.exponent = None
        h = utils.make_handlers(True)
        self.opener = build_opener (* h)
        self.jar = h[1].cookiejar
        self.user_agent = args.ua
        self.nextfile = args.filename if args.filename else "Login"
        self.is_r81 = False

    def ma_login(self):
        logger.info("MAP login started...")

        if not self.nextfile:
            self.signout()

        if not self.args.filepref:
            self.init_paths()
        while self.nextfile:
            spos = self.nextfile.rfind("/")
            tag = self.nextfile[spos + 1:]
            qpos = tag.find("?")
            if qpos > 0:
                tag = tag[:qpos ]
            try:
                logger.info("Current page: '{}'".format(tag))
                getattr(self, tag, None)()
            except:
                raise RuntimeError("Failed to find handler for {}".format(tag))
        logger.info("MAP login finished successfully.")

    def signout(self):
        # Empty post with special headers (Referer)
        so = "/SignOut"
        url = ref = self.args.filepref + "/Portal"
        url += so

        if self.is_r81:
            ref += "/Main"
            base_host = "CPCVPN_BASE_HOST"
            if self.args.cookies and  base_host not in self.args.cookies:
                self.args.cookies += "; {}={}".format(base_host, self.args.host)
        else:
            ref += so

        self._do_request(url, data="", ref_path=ref)
        logger.info("MAP logout done.")

    def init_paths(self):
        self._do_request(self.args.filename)
        pr = utils.parseurl(self.purl)
        # There should be 3 components
        self.args.filepref, _, self.nextfile = filter(None, pr.path.split("/"))
        logger.debug("file={} filepref={}.".format(self.args.filename, self.args.filepref))

    def Login(self):

        self.get_rsa_params()

        for form in self.html.find('form'):
            if form.attrs.get('id') == 'loginForm':
                next_file = form.attrs['action']
                assert form.attrs['method'] == 'post'
                break

        realmsArr = {}
        realms_new = False
        arrname = "realmsArrJSON"
        for script in self.html.find('script'):
            # get main script
            if script.attrs.get("src", None) is None:
                js = script.text

                # Extract initAvailableRealms function source
                m1 = re.search('initAvailableRealms[^{]+{', js)
                m2 = re.search('}[\s]+[\w]+[\s]+isShowRealmsCombobox', js)
                if not (m1 and m2):
                    if arrname not in js:
                        continue

                    i = 0
                    j = -1
                    m2 = re.search(arrname + '[^;]+;', js)
                    if m2:
                        sp = m2.span()
                        arr = js[sp[0]:sp[1]]
                        arr = arr.partition("=")[2]
                        realmsArr = json.loads(arr.strip()[1:-2].replace('\\"', '"'))
                        realmsArr = dict(((i, r) for i, r in enumerate(realmsArr)))
                        realms_new = True
                    else:
                        continue
                else:
                    i = m1.span()[1]
                    j = m2.span()[0]
                src = js[i:j]

                # XXX: make js look like python (hackish hack)
                src = src.replace("false", "False")
                src = src.replace("null", "None")
                src = src.replace("new Array", "dict")
                src = src.replace("\t", "")
                # src = src.replace(" ", "")
                src = src.replace("var", "")
                src = src.replace("||", "or")
                src_py = []
                for s in src.split("\n"):
                    src_py.append(s.strip())
                src = "\n".join(src_py)
                g = {"parseInt":lambda x:int(x)}
                if not realms_new:
                    g["realmsArr"] = realmsArr
                try:
                    exec(src, g)
                    if realms_new:
                        if g["isCaptchaRequired"]:
                            raise RuntimeError("Captcha input NOT supported, use browser to login and extract cookie!")
                except Exception:
                    raise IOError("Failed to fetch realms array, can't proceed further!")
                break

        vpid_prefix = None
        for inp in self.html.find('input'):
            name = inp.attrs.get("name")

            if name == "vpid_prefix":
                vpid_prefix = inp.attrs.get("value")

        loginType = ""

        qusername = qpin = None
        pin = ''
        selectedRealm = self.args.realm
        selectedRealmUI = ""
        realm_opts = []
        for sel in self.html.find('select'):
            if sel.attrs.get("name") == "selectedRealm":
                st = sel.subtags()
                if st:
                    for opt in st:
                        if "disabled" in opt.attrs:
                            continue
                        realm_opts.append((opt.attrs.get("value"), opt.text))
                        if "selected" in opt.attrs:
                            selectedRealmUI = opt.attrs.get("value")
                            continue
                    if not selectedRealmUI:
                        selectedRealmUI = st[0].attrs.get("value")

        # Show errors if any
        for sp in self.html.find('span'):
            if sp.attrs.get("class") == "errorMessage":
                msg = self._fix_br(sp.text)
                if msg:
                    self.ui.wait_input([self.ui.print_header("Login page error: '{}'".format(msg))])
        # Request UI realm input as option text or value
        if not selectedRealm and len(realm_opts) > 1:

            qrealm = self.ui.ask_sel("Select login option", realm_opts)
            selectedRealm = self.ui.wait_input([qrealm])[0]

        if selectedRealm:
            sr = None
            # Check realm exists and convert to value if option text was used
            for val, txt in realm_opts:
                if val == selectedRealm:
                    sr = val
                    break
                if txt == selectedRealm:
                    sr = val
                    break
            if sr is None:
                try:
                    sr = realmsArr.get(int(sr), {}).get('name')
                except:
                    raise RuntimeError("Cant find {} in options".format(selectedRealm))

            selectedRealmUI = sr

        for ri in realmsArr.items():
            logger.debug(ri)
        for ri in realmsArr:
            realm = realmsArr[ri]
            realm_name = realm['name']
            if selectedRealmUI == realm_name or selectedRealm == realm_name:
                break
        selectedRealm = realm['name']
        factor0 = realm['authSchemesInfo'][0]
        amt = factor0['authMethodType']

        # First factors:
        #  2 - username + password
        #  3 - certificate
        #  4 - securid not Keyfob
        #  5 - Radius
        #  7 - securid Keyfob
        #  8 - SAML
        # Second factor:
        #  0 - Special (e.g. password change)
        #  6 - Dynamic ID (delivered by SMS/Email)

        if amt == 8:
            raise RuntimeError("SAML mode not supported. Use regular browser-based login and pass browser cookies to client to init tunnel.")

        self.enc = enc = RSAEnc (self.modulus, self.exponent)
        if amt == 3:
            cert_path = self.args.filepref + "/Login/LoginWithCert?selectedRealm=" + selectedRealm
            self._do_request(cert_path)  # Full path here!
            self.nextfile = self.purl
            return

        if amt not in [1, 3] and not loginType:
            loginType = "Standard"

        qhdr = self.ui.print_header(factor0["customDisplayHeader"])
        username = self.args.username
        if not username:
            qusername = self.ui.ask_str(factor0["customDisplayUserName"])

        # TODO: if amt == 7 - token?
        qpassword = self.ui.ask_pwd(factor0["customDisplayPassword"])

        if amt == 7:
            qpin = self.ui.ask_str('Keyfob PIN')

        vals = self.ui.wait_input([v for v in [qhdr, qusername, qpassword, qpin] if v is not None])
        vals.pop(0)
        if qusername is not None:
            username = vals.pop(0)
        password = vals.pop(0)
        if qpin is not None:
            pin = vals.pop(0)

        d = dict (
            selectedRealm=selectedRealm,
            loginType=loginType,
            userName=username,
            pin=pin,
            password=enc.encrypt (utils.as_bytes(password + pin) + self.zero_tail),  # NOTE: JS seems to do this.
            HeightData=""
            )
        if vpid_prefix:
            d["vpid_prefix"] = vpid_prefix
        data = urlencode (d)

        logger.debug("data {}.".format(data))
        self._do_request(next_file, data=data)  # Full path here!
        self.nextfile = self.purl

    def MultiChallenge(self):
        # Show errors if any
        for div in self.html.find('div'):
            if div.attrs.get("id") == "multiChallengeErrorMessage":
                msg = self._fix_br(div.text)
                if msg:
                    self.ui.wait_input([self.ui.print_header("MultiChallenge page error: '{}'".format(msg))])
        next_file, d, at, hdr = self._parse_pw_response ()
        ask_mthd = self.ui.ask_str if at == 6 else self.ui.ask_pwd

        qh = self.ui.print_header(hdr)
        qotp = ask_mthd('Your input')
        otp = self.ui.wait_input([qh, qotp])[1]
        d.append(('password', self.enc.encrypt (utils.as_bytes(otp) + self.zero_tail)))
        self._do_request(next_file, data=urlencode (d))
        self.nextfile = self.purl

    def ActivateLogin(self):
        self._do_request('sslvpn/Login/ActivateLogin?ActivateLogin=activate&LangSelect=en_US&submit=Continue&HeightData=')
        self.nextfile = self.purl

    def Main(self):
        m = None
        self.extender = None
        # Main -> extender
        for s in self.html.find("script"):
            js = s.text
            m = re.search('snxWin=window.open\(\'([^\']+)\'', js)
            if m:
                self.extender = self.args.host + m.group(1)
                break
            if "Extender.user_name" in s.text:
                self.is_r81 = True
                self.extender = self.purl
                break
        if not self.extender:
            raise RuntimeError("Extender path not found!")

        self.nextfile = None

    def _do_request(self, url, data=None, do_html=True, ref_path="", headers={}):

        def tolist(s):
            return list(filter(lambda x: x, s.split("/")))

        base = '/'.join (['https:/'] + tolist(self.args.host))
        url = '/'.join ([base] + tolist(url))
        if data is not None:
            data = data.encode ()  # allow utf8 stuff
        if ref_path:
            if not ref_path.startswith("http"):
                ref_path = '/'.join ([base] + tolist(ref_path))
            headers.update({"Referer": ref_path})
        if self.args.cookies:
            headers.update({"Cookie":self.args.cookies})
        headers.update({"User-Agent":self.user_agent})
        rq = Request (url, data, headers=headers)

        logger.debug("Open url={}, headers={} cookie {}.".format(url, rq.header_items(), self.jar))
        f = self.opener.open (rq, timeout=1000)
        logger.debug("Response hdrs: {}.".format(f.getheaders()))
        try:
            page = f.read ()
        except IncompleteRead as e:
            page = e.partial
        self.resp = page
        if do_html:
            self._parse_html(page.decode ('utf8'))
            title = self.html.find("title")
            if title:
                logger.debug("page title {}".format(title[0].text.strip()))
        self.purl = f.geturl ()
        self.info = f.info ()
        f.close()

    def _parse_html(self, page):
        self.html = CPHTMLParser()
        self.html.feed(page)

    def get_rsa_params(self):
        logger.debug("RSA params fetch.")
        # Get the RSA parameters from the javascript in the received html
        for script in self.html.find('script'):
            if 'RSA' in script.attrs.get ('src', ''):
                next_file = script.attrs['src']
                break
        else:
            raise IOError('No RSA javascript file found!')

        # next_file should be relative!
        path = self.purl[self.purl.find(self.args.host) + len(self.args.host):]
        path = path[path.find("/"):]
        rsaurl = "/".join(path.split("/")[:-1] + [next_file])
        self._do_request(rsaurl, do_html=False)

        self._parse_rsa_params ()
        logger.debug("n={:x}, e={:x}".format(self.modulus , self.exponent))
        if not (self.modulus and self.exponent):
            raise IOError('No RSA modulus and/or exponent found!')

    def _parse_rsa_params (self):
        data = self.resp.decode ('utf-8')

        for m in re.finditer(r'var[\s]+(modulus|exponent)[\s]+=[\s]+([^\;]+);', data):
            name = m.group(1)
            value = int(m.group(2)[1:-1], 16)
            setattr(self, name, value)

    @staticmethod
    def _fix_br(s):
        return "\n".join(filter(None, [s.strip() for s in re.split("<br[^>]*>", s)]))

    def _parse_pw_response (self):
        """ The password response contains another form where the
            one-time password (in our case received via a message to the
            phone) must be entered.
        """

        for form in self.html.find ('form'):
            if form.attrs.get('name') == 'MCForm':
                next_file = form.attrs['action']
                assert form.attrs['method'] == 'post'
                break

        new_form = False
        for fdiv in form.find ('div'):
            if fdiv.attrs.get("id") == "formField":
                form = fdiv
                new_form = True
        hdr = "MultiChallenge form"
        for div in self.html.find ('div'):
            if div.attrs.get("id") in ["MSG", "multiChallengeHeader"] or \
               div.attrs.get("class") == "input-label":
                hdr = self._fix_br(div.text)
                break
        d = []
        for inp in form.find ('input'):
            if inp.attrs.get ('type') == 'password':
                continue
            nm = inp.attrs.get('name', None)
            if nm is None:
                continue

            if nm in ('password', 'btnCancel'):
                continue

            d.append((inp.attrs['name'], inp.attrs.get ('value', '')))
            # This was hack to prevent error due to bad parsing. Somehow  fixed now, but leave it here just ub case
            # if nm == 'username':
                # break

        # Extract authType value
        for script in self.html.find('script'):
            if script.attrs.get("src", None) is None:
                js = script.text
                m = re.search("authType[^\d]+([\d])", js)
                if m is None:
                    raise RuntimeError("authType not found!")
                at = int(m.group(1))
                break

        if not new_form:
            # Special case or error
            if at == 0:
                for t in form.find ('table'):
                    if t.get("id") == "tblFormFields":
                        s = t.get("style")
                        for kv in s.plit(";"):
                            k, _, v = [e.strip() for e in kv.partition(":")]
                            if k == "display" and v == "none":
                                raise RuntimeError("Authorization failed due to: '{}'".format(hdr))
            elif at == 6:
                for l in form.find ('label'):
                    if l.attrs['for'] == 'passwordDisplayed' and "verification" not in l.text.lower():
                        raise RuntimeError("OTP form is abnormal! Please, use browser to and fix the issue(s) (e.g. check error messages, change expired password etc.).")
                logger.debug("OTP maker found: '{}'.".format(l.text))

        return next_file, d, at, hdr


class TextSocketHandler(SocketHandler):
    sl = struct.Struct("!H")

    def emit(self, record):
        try:
            s = self.format(record)
            s = s.encode()
            n = self.sl.pack(len(s))
            self.sock.sendall(n + s)
            self.send(s)
        except Exception:
            self.handleError(record)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="CheckPoint MA gateway authorization utility.")
    parser.add_argument("server", type=str, help="Gateway server address with optional port.")  # host or host:port or https://host:port
    utils.add_common_client_args(parser)
    parser.add_argument("--so", action='store_true', default=False, help="Do MA Signout request using cookie(s) from previous run or browser data.")
    parser.add_argument("--pipe", action='store_true', default=False, help=argparse.SUPPRESS)
    parser.add_argument("--sp", type=int, default=-1, help=argparse.SUPPRESS)

    utils.add_common_args(parser)
    options = parser.parse_args()
    spipe = options.sp > 0

    ui = cui.TUI()
    if spipe:
        options.pipe = True

    if options.pipe:
        if spipe:
            lh = TextSocketHandler("127.0.0.1", options.sp)
            lh.createSocket()
        else:
            lh = logging.StreamHandler(sys.stdout)
        logger.addHandler(lh)
        lh.setFormatter(logging.Formatter('%(levelname)s:%(message)s'))
        ui = cui.PUI(lh if spipe else None)
    options.ui = ui
    utils.client_setup(options)
    retcode = 0
    try:
        if sys.version_info <= (3, 6):
            raise RuntimeError("Python versions less than 3.7 is not supported!")

        p = utils.parseurl(options.server)
        ssl_ctx.check_ssl_mode(p.host, p.port, False)
        gwi = utils.get_gw_info(options.server)

        cookie_name = gwi.cookie_name

        opts = options
        opts.ua = options.ua
        opts.filename = options.path
        opts.filepref = None
        opts.host = opts.server
        opts.username = opts.user
        opts.cookies = opts.cookies
        opts.realm = opts.realm
        mar = MARequester(opts, ui)
        if options.so:
            mar.init_paths()
            mar.nextfile = pp.join(mar.args.filepref, "Portal", "Main")
            mar.ma_login()
            mar.signout()
            return

        mar.ma_login()
        cookies = []
        for c in mar.jar:
            nm = c.name

            if cookie_name in  nm:
                cookies.append(nm + "=" + c.value)
        reprcookies = "; ".join(cookies)

        logger.info("COOKIES:{}:{}".format(mar.extender, reprcookies))
    except Exception as e:
        retcode = 1
        logger.error(str(e))
    finally:
        logger.info("QUIT:{}".format(retcode))
    quit(retcode)


if __name__ == '__main__':
    main()
