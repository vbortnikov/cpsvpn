# coding: utf-8
# Created on 28.05.2021
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import ssl
import os
import os.path as op
import socket
import datetime
import hashlib
import logging
from importlib import resources
from io import BytesIO as BIO
from contextlib import closing
from . import appdirs
from . import crt
from . import utils

__ssl_strict__ = True
__ssl_cont__ = None

ca_cache = appdirs.user_cache_dir(utils._pkg_)
cached_pem = op.join(ca_cache, "cache.pem")

logger = logging.getLogger()


def set_ssl_strict_mode(state):
    global __ssl_strict__
    __ssl_strict__ = state


def get_ssl_context():
    global __ssl_cont__
    if not __ssl_cont__:
        __ssl_cont__ = ssl.create_default_context()
        pkg_data = utils._pkg_ + ".data"
        try:
            cert_pem = resources.read_text(pkg_data, "cert.pem")
            cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)
            __ssl_cont__ .load_verify_locations(cadata=cert_der)
        except:
            pass
        try:
            with resources.path(pkg_data, 'cl_cert.pem') as certpem:
                with resources.path(pkg_data, 'cl_key.pem') as keypem:
                        __ssl_cont__ .load_cert_chain(certpem, keypem)
        except:
            pass

    context = __ssl_cont__
    if __ssl_strict__:
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


# Build pem cache if does not exist
def _make_pem():

    if os.access(cached_pem, os.F_OK):
        return
    pem = ''
    for fname in os.listdir(ca_cache):
        if fname.endswith(".crt"):
            with open(op.join(ca_cache, fname), "rb") as fcrt:
                pem += ssl.DER_cert_to_PEM_cert(fcrt.read())
    with open(cached_pem, "wt") as fpem:
        fpem.write(pem)
    logger.info("PEM cache for CA chain verification in {} was updated.".format(cached_pem))


def _fetch_all(base):
    if not os.access(ca_cache, os.F_OK):
        os.makedirs(ca_cache)

    context = get_ssl_context()
    stack = [] + base
    visited = set()
    while stack:
        url = stack.pop()
        if url in visited:
            continue
        visited.add(url)
        # check cache and cert date
        urlsha = hashlib.sha1(url.encode())
        name = urlsha.hexdigest()
        cached_ca = op.join(ca_cache, name + ".crt")
        fetch_cert = True
        if os.access(cached_ca, os.F_OK):
            with open(cached_ca, "rb") as fcert:
                der = fcert.read()
                cert = crt.Cert(BIO(der))
                t = cert.get_notafter()
                expired = t.get_time()
                if datetime.datetime.now(datetime.timezone.utc) < expired:
                    fetch_cert = False

        if fetch_cert:
            der = utils.do_https_request(url, rawval=1)
            with open(cached_ca, "wb") as fcert:
                fcert.write(der)
        if fetch_cert and os.access(cached_pem, os.F_OK):
            os.unlink(cached_pem)

        context.load_verify_locations(cadata=der)
        stack.extend(_get_aia(der))
    _make_pem()


def _get_aia(cert):
    ret = []
    fcert = BIO(cert)
    cert = crt.Cert(fcert)
    for url in cert.aia_urls():
        if url.startswith("http"):
            ret.append(url)
    return ret


def _resolve_cert_chain(addr):
    cert = ssl.get_server_certificate(addr)
    _fetch_all(_get_aia(ssl.PEM_cert_to_DER_cert(cert)))


def _test_wrap(host, port):
    with closing(socket.create_connection((host, port))) as sock:
        context = get_ssl_context()
        context.wrap_socket(sock, server_hostname=host)


def check_ssl_mode(host, port, nocert):

        ssl_strict = True
        logger.info("Checking SSL mode.")
        try:
            _test_wrap(host, port)
        except ssl.SSLCertVerificationError as e:
            if nocert:
                ssl_strict = False
            else:
                # py 3.7
                if e.verify_code == 20:
                    logger.info("Fetching certs.")
                    _resolve_cert_chain((host, port))
                    _test_wrap(host, port)
                else:
                    ssl_strict = False
        set_ssl_strict_mode(ssl_strict)
        logger.info("SSL mode is: {}.".format("strict" if ssl_strict else "permissive"))

